use crate::core_vm::VirtualMachine;
use crate::foreign_functions::{
    ForeignFunctionCallbackResult, ForeignFunctionContext, MpcOnlineBuiltin,
};
use crate::net::client_store::{ClientInputIndex, ClientOutputShareCount, ClientShareIndex};
use crate::runtime_hooks::HookEvent;
use crate::value_conversions::{usize_to_vm_i64, value_to_i64, value_to_usize};
use crate::VirtualMachineResult;
use std::cmp::Ordering;
use std::collections::HashSet;
use stoffel_vm_types::core_types::{ArrayRef, ShareData, ShareType, TableRef, Value};

const OUTPUT_SHARE_LIST_MAGIC: &[u8; 5] = b"VMOS1";

pub(crate) const FUNCTION_NAMES: &[&str] = &[
    "create_object",
    "create_array",
    "get_field",
    "get_or_create_array_field",
    "set_field",
    "array_length",
    "array_push",
    "array_concat",
    "array_repeat",
    "array_equals",
    "append",
    "extend",
    "copy",
    "count",
    "index",
    "pop",
    "remove",
    "insert",
    "clear",
    "reverse",
    "sort",
    "delete",
    "len",
    "range",
    "ClientStore.get_number_clients",
    "ClientStore.get_number_input_clients",
    "ClientStore.get_number_output_clients",
    "ClientStore.take_share",
    "ClientStore.take_share_bool",
    "ClientStore.take_share_fixed",
    "ClientStore.sum_shares",
    "ClientStore.sum_shares_bool",
    "ClientStore.sum_shares_fixed",
    "LocalStorage.store",
    "LocalStorage.load",
    "LocalStorage.retrieve",
    "LocalStorage.delete",
    "LocalStorage.exists",
    "MpcOutput.send_to_client",
    "create_closure",
    "call_closure",
    "get_upvalue",
    "set_upvalue",
    "print",
    "type",
    "slice",
    "contains",
    "to_string",
    "assert",
];

pub(crate) fn register(vm: &mut VirtualMachine) -> VirtualMachineResult<()> {
    macro_rules! register_standard_builtin {
        ($name:expr, $func:expr) => {
            vm.try_register_typed_foreign_function($name, $func)?;
        };
    }

    register_standard_builtin!("create_object", |mut ctx| ctx.create_object());

    register_standard_builtin!("create_array", |mut ctx| {
        let capacity = ctx
            .arg(0)
            .map(|value| value_to_usize(value, "array capacity"))
            .transpose()?
            .unwrap_or(0);

        ctx.create_array(capacity)
    });

    register_standard_builtin!("get_field", |mut ctx| {
        let (table_ref, key) = {
            let args = ctx.named_args("get_field");
            args.require_min(2, "at least 2 arguments: object and key")?;
            let target = args.cloned(0)?;
            let key = args.cloned(1)?;
            if let Value::String(value) = target {
                let len = value.chars().count();
                let index = resolve_pythonic_index(&key, len, "string index")?;
                return match value.chars().nth(index) {
                    Some(ch) => Ok(Value::String(ch.to_string())),
                    None => {
                        Err(format!("string index {} out of range (length {})", index, len).into())
                    }
                };
            }
            let Some(table_ref) = TableRef::from_value(&target) else {
                return Ok(Value::Unit);
            };
            (table_ref, key)
        };

        let key = if let TableRef::Array(array_ref) = table_ref {
            let len = ctx.read_array_ref_len(array_ref)?;
            resolve_array_key(&key, len, "array index")?
        } else {
            key
        };

        let value = match ctx.read_table_field(table_ref, &key)? {
            Some(value) => value,
            // Missing object/dict keys read as Unit; array reads are bounds-checked.
            None => match (table_ref, value_to_usize(&key, "array index")) {
                (TableRef::Array(array_ref), Ok(index)) => {
                    let len = ctx.read_array_ref_len(array_ref)?;
                    return Err(
                        format!("array index {} out of range (length {})", index, len).into(),
                    );
                }
                _ => Value::Unit,
            },
        };

        if ctx.hooks_enabled() {
            match table_ref {
                TableRef::Object(object_ref) => {
                    let event = HookEvent::ObjectFieldRead(object_ref, key, value.clone());
                    ctx.trigger_hook_with_snapshot(&event)?;
                }
                TableRef::Array(array_ref) => {
                    let event = HookEvent::ArrayElementRead(array_ref, key, value.clone());
                    ctx.trigger_hook_with_snapshot(&event)?;
                }
            }
        }

        Ok(value)
    });

    register_standard_builtin!("get_or_create_array_field", |mut ctx| {
        let (table_ref, key) = {
            let args = ctx.named_args("get_or_create_array_field");
            args.require_min(2, "at least 2 arguments: object and key")?;
            (args.table_ref(0, "First argument")?, args.cloned(1)?)
        };

        let key = if let TableRef::Array(array_ref) = table_ref {
            let len = ctx.read_array_ref_len(array_ref)?;
            resolve_array_key(&key, len, "array index")?
        } else {
            key
        };

        match ctx.read_table_field(table_ref, &key)? {
            Some(value) if TableRef::from_value(&value).is_some() => Ok(value),
            Some(value) if value != Value::Unit => {
                Err("Cannot autovivify nested list through a non-list value".into())
            }
            _ => {
                let inner_ref = ctx.create_array_ref(0)?;
                let inner_value = Value::from(inner_ref);
                ctx.set_table_field(table_ref, key, inner_value.clone())?;
                Ok(inner_value)
            }
        }
    });

    register_standard_builtin!("set_field", |mut ctx| {
        let (table_ref, key, new_value) = {
            let args = ctx.named_args("set_field");
            args.require_min(3, "3 arguments: object, key, and value")?;
            (
                args.table_ref(0, "First argument")?,
                args.cloned(1)?,
                args.cloned(2)?,
            )
        };
        let key = if let TableRef::Array(array_ref) = table_ref {
            let len = ctx.read_array_ref_len(array_ref)?;
            resolve_array_key(&key, len, "array index")?
        } else {
            key
        };

        let hooks_enabled = ctx.hooks_enabled();
        if !hooks_enabled {
            ctx.set_table_field(table_ref, key, new_value)?;
            return Ok(Value::Unit);
        }

        let old_value = ctx
            .read_table_field(table_ref, &key)?
            .unwrap_or(Value::Unit);
        ctx.set_table_field(table_ref, key.clone(), new_value.clone())?;
        match table_ref {
            TableRef::Object(object_ref) => {
                let event = HookEvent::ObjectFieldWrite(object_ref, key, old_value, new_value);
                ctx.trigger_hook_with_snapshot(&event)?;
            }
            TableRef::Array(array_ref) => {
                let event = HookEvent::ArrayElementWrite(array_ref, key, old_value, new_value);
                ctx.trigger_hook_with_snapshot(&event)?;
            }
        }

        Ok(Value::Unit)
    });

    register_standard_builtin!("array_length", |mut ctx| {
        let len = {
            let args = ctx.named_args("array_length");
            args.require_exact(1, "1 argument: array")?;
            let value = args.cloned(0)?;
            if let Value::String(value) = value {
                value.chars().count()
            } else {
                let Some(array_ref) =
                    TableRef::from_value(&value).and_then(|table_ref| match table_ref {
                        TableRef::Array(array_ref) => Some(array_ref),
                        TableRef::Object(_) => None,
                    })
                else {
                    return Err("First argument must be an array or string".into());
                };
                ctx.read_array_ref_len(array_ref)?
            }
        };

        let len = usize_to_vm_i64(len, "array length")?;
        Ok(Value::I64(len))
    });

    register_standard_builtin!("array_push", |mut ctx| {
        let array_ref = {
            let args = ctx.named_args("array_push");
            args.require_min(2, "at least 2 arguments: array and value")?;
            args.array_ref(0, "First argument")?
        };

        let len = ctx.push_array_args_from(array_ref, 1, "array_push")?;
        Ok(Value::I64(usize_to_vm_i64(len, "array length")?))
    });

    register_standard_builtin!("array_concat", |mut ctx| {
        let (left_ref, right_ref) = {
            let args = ctx.named_args("array_concat");
            args.require_exact(2, "2 arguments: left array and right array")?;
            (
                args.array_ref(0, "First argument")?,
                args.array_ref(1, "Second argument")?,
            )
        };

        let left_len = ctx.read_array_ref_len(left_ref)?;
        let right_len = ctx.read_array_ref_len(right_ref)?;
        let capacity = left_len
            .checked_add(right_len)
            .ok_or_else(|| "array_concat result length is too large".to_owned())?;
        let result_ref = ctx.create_array_ref(capacity)?;

        for source_ref in [left_ref, right_ref] {
            let len = ctx.read_array_ref_len(source_ref)?;
            for index in 0..len {
                let value = ctx
                    .read_table_field(TableRef::from(source_ref), &Value::I64(index as i64))?
                    .unwrap_or(Value::Unit);
                ctx.push_array_ref_values(result_ref, &[value])?;
            }
        }

        Ok(Value::from(result_ref))
    });

    register_standard_builtin!("array_repeat", |mut ctx| {
        let (array_ref, count) = {
            let args = ctx.named_args("array_repeat");
            args.require_exact(2, "2 arguments: array and count")?;
            let count = value_to_i64(args.get(1)?, "repeat count")?;
            (
                args.array_ref(0, "First argument")?,
                usize::try_from(count.max(0))
                    .map_err(|_| "repeat count is too large".to_owned())?,
            )
        };

        let values = collect_array_values(&mut ctx, array_ref)?;
        let capacity = values
            .len()
            .checked_mul(count)
            .ok_or_else(|| "array_repeat result length is too large".to_owned())?;
        let result_ref = ctx.create_array_ref(capacity)?;
        for _ in 0..count {
            ctx.push_array_ref_values(result_ref, &values)?;
        }

        Ok(Value::from(result_ref))
    });

    register_standard_builtin!("array_equals", |mut ctx| {
        let (left_ref, right_ref) = {
            let args = ctx.named_args("array_equals");
            args.require_exact(2, "2 arguments: left array and right array")?;
            (
                args.array_ref(0, "First argument")?,
                args.array_ref(1, "Second argument")?,
            )
        };

        Ok(Value::Bool(arrays_equal(
            &mut ctx, left_ref, right_ref, 64,
        )?))
    });

    register_standard_builtin!("append", |mut ctx| {
        let array_ref = {
            let args = ctx.named_args("append");
            args.require_min(2, "at least 2 arguments: array and value")?;
            args.array_ref(0, "First argument")?
        };

        ctx.push_array_args_from(array_ref, 1, "append")?;
        Ok(Value::Unit)
    });

    register_standard_builtin!("extend", |mut ctx| {
        let (array_ref, values_ref) = {
            let args = ctx.named_args("extend");
            args.require_exact(2, "2 arguments: array and values")?;
            (
                args.array_ref(0, "First argument")?,
                args.array_ref(1, "Second argument")?,
            )
        };

        let values = collect_array_values(&mut ctx, values_ref)?;
        ctx.push_array_ref_values(array_ref, &values)?;
        Ok(Value::Unit)
    });

    register_standard_builtin!("copy", |mut ctx| {
        let array_ref = {
            let args = ctx.named_args("copy");
            args.require_exact(1, "1 argument: array")?;
            args.array_ref(0, "First argument")?
        };

        let values = collect_array_values(&mut ctx, array_ref)?;
        let result_ref = ctx.create_array_ref(values.len())?;
        ctx.push_array_ref_values(result_ref, &values)?;
        Ok(Value::from(result_ref))
    });

    register_standard_builtin!("count", |mut ctx| {
        let (array_ref, needle) = {
            let args = ctx.named_args("count");
            args.require_exact(2, "2 arguments: array and value")?;
            (args.array_ref(0, "First argument")?, args.cloned(1)?)
        };

        let mut count = 0usize;
        for value in collect_array_values(&mut ctx, array_ref)? {
            if values_equal(&mut ctx, &value, &needle, 64)? {
                count = count
                    .checked_add(1)
                    .ok_or_else(|| "count result is too large".to_owned())?;
            }
        }

        Ok(Value::I64(usize_to_vm_i64(count, "count")?))
    });

    register_standard_builtin!("index", |mut ctx| {
        let (array_ref, needle, start_arg, stop_arg) = {
            let args = ctx.named_args("index");
            args.require_min(2, "at least 2 arguments: array and value")?;
            if args.len() > 4 {
                return Err(
                    "index expects at most 4 arguments: array, value, start, and stop".into(),
                );
            }
            (
                args.array_ref(0, "First argument")?,
                args.cloned(1)?,
                if args.len() >= 3 {
                    Some(args.cloned(2)?)
                } else {
                    None
                },
                if args.len() >= 4 {
                    Some(args.cloned(3)?)
                } else {
                    None
                },
            )
        };

        let values = collect_array_values(&mut ctx, array_ref)?;
        let (start, stop) = normalize_search_bounds(start_arg, stop_arg, values.len())?;
        for (index, value) in values.into_iter().enumerate().take(stop).skip(start) {
            if values_equal(&mut ctx, &value, &needle, 64)? {
                return Ok(Value::I64(usize_to_vm_i64(index, "index")?));
            }
        }

        Err("value is not in list".into())
    });

    register_standard_builtin!("pop", |mut ctx| {
        let (array_ref, index_arg) = {
            let args = ctx.named_args("pop");
            args.require_min(1, "at least 1 argument: array")?;
            if args.len() > 2 {
                return Err("pop expects at most 2 arguments: array and optional index".into());
            }
            (
                args.array_ref(0, "First argument")?,
                if args.len() == 2 {
                    Some(args.cloned(1)?)
                } else {
                    None
                },
            )
        };

        let len = ctx.read_array_ref_len(array_ref)?;
        if len == 0 {
            return Err("pop from empty list".into());
        }
        let index = match index_arg {
            Some(value) => normalize_existing_index(value_to_i64(&value, "index")?, len)?,
            None => len - 1,
        };
        ctx.pop_array_ref_value(array_ref, index)?
            .ok_or_else(|| "pop index out of range".into())
    });

    register_standard_builtin!("remove", |mut ctx| {
        let (array_ref, needle) = {
            let args = ctx.named_args("remove");
            args.require_exact(2, "2 arguments: array and value")?;
            (args.array_ref(0, "First argument")?, args.cloned(1)?)
        };

        for (index, value) in collect_array_values(&mut ctx, array_ref)?
            .into_iter()
            .enumerate()
        {
            if values_equal(&mut ctx, &value, &needle, 64)? {
                ctx.pop_array_ref_value(array_ref, index)?;
                return Ok(Value::Unit);
            }
        }

        Err("value is not in list".into())
    });

    register_standard_builtin!("insert", |mut ctx| {
        let (array_ref, raw_index, value) = {
            let args = ctx.named_args("insert");
            args.require_exact(3, "3 arguments: array, index, and value")?;
            (
                args.array_ref(0, "First argument")?,
                value_to_i64(args.get(1)?, "index")?,
                args.cloned(2)?,
            )
        };

        let len = ctx.read_array_ref_len(array_ref)?;
        let index = normalize_insert_index(raw_index, len);
        ctx.insert_array_ref_value(array_ref, index, value)?;
        Ok(Value::Unit)
    });

    register_standard_builtin!("clear", |mut ctx| {
        let array_ref = {
            let args = ctx.named_args("clear");
            args.require_exact(1, "1 argument: array")?;
            args.array_ref(0, "First argument")?
        };

        ctx.clear_array_ref(array_ref)?;
        Ok(Value::Unit)
    });

    register_standard_builtin!("reverse", |mut ctx| {
        let array_ref = {
            let args = ctx.named_args("reverse");
            args.require_exact(1, "1 argument: array")?;
            args.array_ref(0, "First argument")?
        };

        ctx.reverse_array_ref(array_ref)?;
        Ok(Value::Unit)
    });

    register_standard_builtin!("sort", |mut ctx| {
        let array_ref = {
            let args = ctx.named_args("sort");
            args.require_exact(1, "1 argument: array")?;
            args.array_ref(0, "First argument")?
        };

        let mut values = collect_array_values(&mut ctx, array_ref)?;
        sort_values(&mut values)?;
        ctx.replace_array_ref_values(array_ref, values)?;
        Ok(Value::Unit)
    });

    register_standard_builtin!("delete", |mut ctx| {
        let (array_ref, raw_index) = {
            let args = ctx.named_args("delete");
            args.require_exact(2, "2 arguments: array and index")?;
            (
                args.array_ref(0, "First argument")?,
                value_to_i64(args.get(1)?, "index")?,
            )
        };

        let len = ctx.read_array_ref_len(array_ref)?;
        let index = normalize_existing_index(raw_index, len)?;
        ctx.pop_array_ref_value(array_ref, index)?;
        Ok(Value::Unit)
    });

    register_standard_builtin!("len", |mut ctx| {
        let len = {
            let args = ctx.named_args("len");
            args.require_exact(1, "1 argument: array")?;
            let value = args.cloned(0)?;
            if let Value::String(value) = value {
                value.chars().count()
            } else {
                let Some(array_ref) =
                    TableRef::from_value(&value).and_then(|table_ref| match table_ref {
                        TableRef::Array(array_ref) => Some(array_ref),
                        TableRef::Object(_) => None,
                    })
                else {
                    return Err("First argument must be an array or string".into());
                };
                ctx.read_array_ref_len(array_ref)?
            }
        };

        let len = usize_to_vm_i64(len, "array length")?;
        Ok(Value::I64(len))
    });

    register_standard_builtin!("range", |mut ctx| {
        let (start, stop, step) = {
            let args = ctx.named_args("range");
            args.require_min(2, "at least 2 arguments: start and stop")?;
            if args.len() > 3 {
                return Err("range expects at most 3 arguments: start, stop, and step".into());
            }
            (
                value_to_i64(&args.cloned(0)?, "range start")?,
                value_to_i64(&args.cloned(1)?, "range stop")?,
                if args.len() == 3 {
                    value_to_i64(&args.cloned(2)?, "range step")?
                } else {
                    1
                },
            )
        };
        if step == 0 {
            return Err("range step argument must not be zero".into());
        }

        let count = stepped_range_len(start, stop, step)?;
        let array_ref = ctx.create_array_ref(count)?;
        if count > 0 {
            let mut values = Vec::with_capacity(count);
            let mut value = start;
            for _ in 0..count {
                values.push(Value::I64(value));
                value = value
                    .checked_add(step)
                    .ok_or_else(|| "range value overflowed i64".to_owned())?;
            }
            ctx.push_array_ref_values(array_ref, &values)?;
        }
        Ok(Value::from(array_ref))
    });

    register_standard_builtin!("ClientStore.get_number_clients", |ctx| {
        let count = ctx.client_store_len();
        Ok(Value::I64(usize_to_vm_i64(count, "client count")?))
    });

    register_standard_builtin!("ClientStore.get_number_input_clients", |ctx| {
        let count = ctx.input_client_count();
        Ok(Value::I64(usize_to_vm_i64(count, "input client count")?))
    });

    register_standard_builtin!("ClientStore.get_number_output_clients", |ctx| {
        let count = ctx.output_client_count();
        Ok(Value::I64(usize_to_vm_i64(count, "output client count")?))
    });

    register_standard_builtin!("ClientStore.take_share", |ctx| {
        let args = ctx.named_args("ClientStore.take_share");
        args.require_exact(2, "2 arguments: client_index, share_index")?;

        let client_index = ClientInputIndex::new(args.usize(0, "client_index")?);
        let share_index = ClientShareIndex::new(args.usize(1, "share_index")?);

        let client_id = ctx
            .client_id_at_index(client_index)
            .ok_or_else(|| format!("No client at index {}", client_index))?;

        Ok(ctx.load_client_share(client_id, share_index)?)
    });

    register_standard_builtin!("ClientStore.take_share_bool", |ctx| {
        let args = ctx.named_args("ClientStore.take_share_bool");
        args.require_exact(2, "2 arguments: client_index, share_index")?;

        let client_index = ClientInputIndex::new(args.usize(0, "client_index")?);
        let share_index = ClientShareIndex::new(args.usize(1, "share_index")?);

        // Load the client's secret input as a boolean (1-bit) share so it can be
        // consumed by the secret-bool gates (NOT/AND/XOR). Plain `take_share`
        // yields a default 64-bit integer share, which those gates reject.
        Ok(ctx.load_client_share_at_as(client_index, share_index, ShareType::boolean())?)
    });

    register_standard_builtin!("ClientStore.take_share_fixed", |ctx| {
        let args = ctx.named_args("ClientStore.take_share_fixed");
        args.require_exact(2, "2 arguments: client_index, share_index")?;

        let client_index = ClientInputIndex::new(args.usize(0, "client_index")?);
        let share_index = ClientShareIndex::new(args.usize(1, "share_index")?);

        Ok(ctx.load_client_share_at_as(
            client_index,
            share_index,
            ShareType::default_secret_fixed_point(),
        )?)
    });

    macro_rules! register_client_share_sum {
        ($name:literal, $fallback_type:expr) => {
            register_standard_builtin!($name, |ctx| {
                let args = ctx.named_args($name);
                args.require_exact(2, "2 arguments: share_index, client_count")?;

                let share_index = ClientShareIndex::new(args.usize(0, "share_index")?);
                // The source loop always reads client zero before checking its bound,
                // so zero and negative bounds both mean one contributing client.
                let client_count = usize::try_from(args.i64(1, "client_count")?.max(1))
                    .map_err(|_| "client_count is too large for this platform")?;
                Ok(ctx.sum_client_shares_at(share_index, client_count, $fallback_type)?)
            });
        };
    }

    register_client_share_sum!("ClientStore.sum_shares", ShareType::default_secret_int());
    register_client_share_sum!("ClientStore.sum_shares_bool", ShareType::boolean());
    register_client_share_sum!(
        "ClientStore.sum_shares_fixed",
        ShareType::default_secret_fixed_point()
    );

    register_standard_builtin!("LocalStorage.store", |mut ctx| {
        let (key_value, stored_value) = {
            let args = ctx.named_args("LocalStorage.store");
            args.require_exact(2, "2 arguments: key and value")?;
            (args.cloned(0)?, args.cloned(1)?)
        };
        let key = local_storage_key(&mut ctx, key_value)?;
        ctx.local_storage_store_value(&key, &stored_value)?;
        Ok(Value::Bool(true))
    });

    register_standard_builtin!("LocalStorage.load", |mut ctx| {
        let key_value = {
            let args = ctx.named_args("LocalStorage.load");
            args.require_exact(1, "1 argument: key")?;
            args.cloned(0)?
        };
        let key = local_storage_key(&mut ctx, key_value)?;
        Ok(ctx.local_storage_load_value(&key)?.unwrap_or(Value::Unit))
    });

    register_standard_builtin!("LocalStorage.retrieve", |mut ctx| {
        let key_value = {
            let args = ctx.named_args("LocalStorage.retrieve");
            args.require_exact(1, "1 argument: key")?;
            args.cloned(0)?
        };
        let key = local_storage_key(&mut ctx, key_value)?;
        Ok(ctx.local_storage_load_value(&key)?.unwrap_or(Value::Unit))
    });

    register_standard_builtin!("LocalStorage.delete", |mut ctx| {
        let key_value = {
            let args = ctx.named_args("LocalStorage.delete");
            args.require_exact(1, "1 argument: key")?;
            args.cloned(0)?
        };
        let key = local_storage_key(&mut ctx, key_value)?;
        Ok(Value::Bool(ctx.local_storage_delete(&key)?))
    });

    register_standard_builtin!("LocalStorage.exists", |mut ctx| {
        let key_value = {
            let args = ctx.named_args("LocalStorage.exists");
            args.require_exact(1, "1 argument: key")?;
            args.cloned(0)?
        };
        let key = local_storage_key(&mut ctx, key_value)?;
        Ok(Value::Bool(ctx.local_storage_exists(&key)?))
    });

    vm.try_register_mpc_online_foreign_function(
        MpcOnlineBuiltin::OutputSendToClient,
        |mut ctx| {
            let (client_id, output_value) = {
                let args = ctx.named_args("MpcOutput.send_to_client");
                args.require_exact(2, "2 arguments: client_id, share_value")?;
                (args.usize(0, "client_id")?, args.cloned(1)?)
            };

            let (share_bytes, share_count) = match &output_value {
                Value::Array(_) => {
                    let Some((_share_type, share_data)) = ctx.extract_homogeneous_share_array(
                        &output_value,
                        "MpcOutput.send_to_client share_value",
                    )?
                    else {
                        return Err(
                            "MpcOutput.send_to_client requires at least one output share".into(),
                        );
                    };
                    let share_count = ClientOutputShareCount::try_new(share_data.len())
                        .map_err(|error| error.to_string())?;
                    (encode_output_share_list(&share_data)?, share_count)
                }
                _ => {
                    let (_share_type, share_data) = ctx.extract_share_data(&output_value)?;
                    (
                        share_data.as_bytes().to_vec(),
                        ClientOutputShareCount::one(),
                    )
                }
            };

            ctx.send_output_to_client(client_id, &share_bytes, share_count)?;

            Ok(Value::Bool(true))
        },
    )?;

    register_standard_builtin!("create_closure", |mut ctx| {
        let (function_name, upvalue_names) = {
            let args = ctx.named_args("create_closure");
            args.require_min(1, "at least 1 argument: function_name")?;
            let function_name = args.cloned_string(0, "First argument")?;

            let mut upvalue_names = Vec::new();
            for arg in args.tail_from(1)? {
                match arg {
                    Value::String(name) => upvalue_names.push(name.clone()),
                    _ => return Err("Upvalue names must be strings".into()),
                }
            }

            (function_name, upvalue_names)
        };

        Ok(ctx.create_closure_value(function_name, &upvalue_names)?)
    });

    register_standard_builtin!("call_closure", |mut ctx| {
        let (closure_value, closure_args) = {
            let args = ctx.named_args("call_closure");
            args.require_min(1, "at least 1 argument: closure")?;
            (args.cloned(0)?, args.tail_from(1)?.to_vec())
        };

        ctx.call_closure_value(&closure_value, &closure_args)?;
        Ok(Value::Unit)
    });

    register_standard_builtin!("get_upvalue", |ctx| {
        let args = ctx.named_args("get_upvalue");
        args.require_exact(1, "1 argument: name")?;
        let name = args.string(0, "Upvalue name")?;

        Ok(ctx.get_upvalue_value(name)?)
    });

    register_standard_builtin!("set_upvalue", |mut ctx| {
        let (name, new_value) = {
            let args = ctx.named_args("set_upvalue");
            args.require_min(2, "2 arguments: name and value")?;
            (args.cloned_string(0, "Upvalue name")?, args.cloned(1)?)
        };

        ctx.set_upvalue_value(&name, new_value)?;
        Ok(Value::Unit)
    });

    register_standard_builtin!("print", |mut ctx| {
        let args = ctx.args().to_vec();
        let mut output = String::new();
        for (i, arg) in args.iter().enumerate() {
            if i > 0 {
                output.push(' ');
            }
            output.push_str(&format_print_value(&mut ctx, arg, 3, &mut HashSet::new())?);
        }
        ctx.write_output_line(&output)?;
        Ok(Value::Unit)
    });

    register_standard_builtin!("type", |ctx| {
        let args = ctx.named_args("type");
        args.require_exact(1, "1 argument")?;

        Ok(Value::String(args.get(0)?.type_name().to_string()))
    });

    register_standard_builtin!("to_string", |mut ctx| {
        let value = {
            let args = ctx.named_args("to_string");
            args.require_exact(1, "1 argument")?;
            args.cloned(0)?
        };
        let text = format_print_value(&mut ctx, &value, 3, &mut HashSet::new())?;
        Ok(Value::String(text))
    });

    register_standard_builtin!("assert", |ctx| {
        let args = ctx.named_args("assert");
        args.require_min(1, "1 or 2 arguments: condition and optional message")?;
        let condition = args.cloned(0)?;
        let message = match args.cloned(1) {
            Ok(Value::String(message)) => Some(message),
            _ => None,
        };
        match condition {
            Value::Bool(true) => Ok(Value::Unit),
            Value::Bool(false) => Err(message
                .unwrap_or_else(|| "assertion failed".to_owned())
                .into()),
            other => Err(format!(
                "assert condition must be a bool, found {}",
                other.type_name()
            )
            .into()),
        }
    });

    register_standard_builtin!("contains", |mut ctx| {
        let (container, needle) = {
            let args = ctx.named_args("contains");
            args.require_exact(2, "2 arguments: container and value")?;
            (args.cloned(0)?, args.cloned(1)?)
        };

        if let Value::String(haystack) = &container {
            let Value::String(needle) = &needle else {
                return Err("'in' on a string requires a string operand".into());
            };
            return Ok(Value::Bool(haystack.contains(needle.as_str())));
        }

        match TableRef::from_value(&container) {
            Some(TableRef::Array(array_ref)) => {
                for value in collect_array_values(&mut ctx, array_ref)? {
                    if values_equal(&mut ctx, &value, &needle, 64)? {
                        return Ok(Value::Bool(true));
                    }
                }
                Ok(Value::Bool(false))
            }
            Some(table_ref @ TableRef::Object(_)) => Ok(Value::Bool(
                ctx.read_table_field(table_ref, &needle)?.is_some(),
            )),
            None => Err(format!(
                "'in' requires a list, dict, or string container, found {}",
                container.type_name()
            )
            .into()),
        }
    });

    register_standard_builtin!("slice", |mut ctx| {
        let (container, start, stop, step) = {
            let args = ctx.named_args("slice");
            args.require_min(3, "at least 3 arguments: value, start, and stop")?;
            if args.len() > 4 {
                return Err(
                    "slice expects at most 4 arguments: value, start, stop, and step".into(),
                );
            }
            (
                args.cloned(0)?,
                args.cloned(1)?,
                args.cloned(2)?,
                if args.len() == 4 {
                    args.cloned(3)?
                } else {
                    Value::I64(1)
                },
            )
        };

        if let Value::String(text) = &container {
            let len = text.chars().count();
            let indices = resolve_slice_indices(&start, &stop, &step, len)?;
            let chars: Vec<char> = text.chars().collect();
            let sliced: String = indices.into_iter().map(|index| chars[index]).collect();
            return Ok(Value::String(sliced));
        }

        let Some(TableRef::Array(array_ref)) = TableRef::from_value(&container) else {
            return Err(format!(
                "slice requires a list or string, found {}",
                container.type_name()
            )
            .into());
        };
        let len = ctx.read_array_ref_len(array_ref)?;
        let indices = resolve_slice_indices(&start, &stop, &step, len)?;
        let result_ref = ctx.create_array_ref(indices.len())?;
        for index in indices {
            let value = ctx
                .read_table_field(TableRef::from(array_ref), &Value::I64(index as i64))?
                .unwrap_or(Value::Unit);
            ctx.push_array_ref_values(result_ref, &[value])?;
        }
        Ok(Value::from(result_ref))
    });

    Ok(())
}

/// Extracts a signed index from an integer Value.
fn value_to_signed_index(value: &Value, name: &str) -> Result<i128, String> {
    match value {
        Value::I64(v) => Ok(*v as i128),
        Value::I32(v) => Ok(*v as i128),
        Value::I16(v) => Ok(*v as i128),
        Value::I8(v) => Ok(*v as i128),
        Value::U64(v) => Ok(*v as i128),
        Value::U32(v) => Ok(*v as i128),
        Value::U16(v) => Ok(*v as i128),
        Value::U8(v) => Ok(*v as i128),
        other => Err(format!(
            "{} must be an integer, found {}",
            name,
            other.type_name()
        )),
    }
}

/// Resolves a possibly-negative index Pythonically: -1 is the last element.
fn resolve_pythonic_index(key: &Value, len: usize, name: &str) -> Result<usize, String> {
    let index = value_to_signed_index(key, name)?;
    let resolved = if index < 0 {
        index + len as i128
    } else {
        index
    };
    usize::try_from(resolved)
        .map_err(|_| format!("{} {} out of range (length {})", name, index, len))
}

/// Resolves negative integer array keys Pythonically, leaving other keys as-is.
fn resolve_array_key(key: &Value, len: usize, name: &str) -> Result<Value, String> {
    match value_to_signed_index(key, name) {
        Ok(index) if index < 0 => {
            let resolved = resolve_pythonic_index(key, len, name)?;
            Ok(Value::I64(resolved as i64))
        }
        _ => Ok(key.clone()),
    }
}

fn is_omitted_slice_bound(value: &Value) -> bool {
    matches!(value, Value::Unit | Value::I64(i64::MAX))
}

fn slice_bound_to_i128(value: &Value, name: &str) -> Result<i128, String> {
    value_to_signed_index(value, name)
}

fn resolve_slice_indices(
    start: &Value,
    stop: &Value,
    step: &Value,
    len: usize,
) -> Result<Vec<usize>, String> {
    let step = value_to_signed_index(step, "slice step")?;
    if step == 0 {
        return Err("slice step cannot be zero".to_owned());
    }

    let len_i = i128::try_from(len).map_err(|_| "slice length is too large".to_owned())?;
    let (mut start_i, stop_i) = if step > 0 {
        let start_i = if is_omitted_slice_bound(start) {
            0
        } else {
            let raw = slice_bound_to_i128(start, "slice start")?;
            if raw < 0 {
                raw + len_i
            } else {
                raw
            }
        }
        .clamp(0, len_i);

        let stop_i = if is_omitted_slice_bound(stop) {
            len_i
        } else {
            let raw = slice_bound_to_i128(stop, "slice stop")?;
            if raw < 0 {
                raw + len_i
            } else {
                raw
            }
        }
        .clamp(0, len_i);

        (start_i, stop_i)
    } else {
        let start_i = if is_omitted_slice_bound(start) {
            len_i - 1
        } else {
            let raw = slice_bound_to_i128(start, "slice start")?;
            if raw < 0 {
                raw + len_i
            } else {
                raw
            }
        }
        .clamp(-1, len_i - 1);

        let stop_i = if is_omitted_slice_bound(stop) {
            -1
        } else {
            let raw = slice_bound_to_i128(stop, "slice stop")?;
            if raw < 0 {
                raw + len_i
            } else {
                raw
            }
        }
        .clamp(-1, len_i - 1);

        (start_i, stop_i)
    };

    let mut indices = Vec::new();
    if step > 0 {
        while start_i < stop_i {
            indices
                .push(usize::try_from(start_i).map_err(|_| "slice index is too large".to_owned())?);
            start_i += step;
        }
    } else {
        while start_i > stop_i {
            indices
                .push(usize::try_from(start_i).map_err(|_| "slice index is too large".to_owned())?);
            start_i += step;
        }
    }
    Ok(indices)
}

fn format_print_value(
    ctx: &mut ForeignFunctionContext<'_>,
    value: &Value,
    max_depth: usize,
    active_tables: &mut HashSet<TableRef>,
) -> ForeignFunctionCallbackResult<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Array(array_ref) => {
            let table_ref = TableRef::from(*array_ref);
            if !active_tables.insert(table_ref) {
                return Ok(format!("Array({}) <cycle>", array_ref.id()));
            }
            let formatted = format_print_array(ctx, *array_ref, max_depth, active_tables);
            active_tables.remove(&table_ref);
            formatted
        }
        Value::Object(object_ref) => {
            let table_ref = TableRef::from(*object_ref);
            if !active_tables.insert(table_ref) {
                return Ok(format!("Object({}) <cycle>", object_ref.id()));
            }
            let formatted = format_print_object(ctx, *object_ref, max_depth, active_tables);
            active_tables.remove(&table_ref);
            formatted
        }
        _ => Ok(format!("{:?}", value)),
    }
}

fn collect_array_values(
    ctx: &mut ForeignFunctionContext<'_>,
    array_ref: ArrayRef,
) -> ForeignFunctionCallbackResult<Vec<Value>> {
    let len = ctx.read_array_ref_len(array_ref)?;
    let mut values = Vec::with_capacity(len);
    for index in 0..len {
        let index = usize_to_vm_i64(index, "array index")?;
        values.push(
            ctx.read_table_field(TableRef::from(array_ref), &Value::I64(index))?
                .unwrap_or(Value::Unit),
        );
    }
    Ok(values)
}

fn values_equal(
    ctx: &mut ForeignFunctionContext<'_>,
    left: &Value,
    right: &Value,
    max_depth: usize,
) -> ForeignFunctionCallbackResult<bool> {
    match (left, right) {
        (Value::Array(left_ref), Value::Array(right_ref)) => {
            arrays_equal(ctx, *left_ref, *right_ref, max_depth)
        }
        _ => Ok(left == right),
    }
}

fn arrays_equal(
    ctx: &mut ForeignFunctionContext<'_>,
    left_ref: ArrayRef,
    right_ref: ArrayRef,
    max_depth: usize,
) -> ForeignFunctionCallbackResult<bool> {
    if left_ref == right_ref {
        return Ok(true);
    }
    if max_depth == 0 {
        return Ok(false);
    }

    let left_len = ctx.read_array_ref_len(left_ref)?;
    let right_len = ctx.read_array_ref_len(right_ref)?;
    if left_len != right_len {
        return Ok(false);
    }

    for index in 0..left_len {
        let key = Value::I64(usize_to_vm_i64(index, "array index")?);
        let left_value = ctx
            .read_table_field(TableRef::from(left_ref), &key)?
            .unwrap_or(Value::Unit);
        let right_value = ctx
            .read_table_field(TableRef::from(right_ref), &key)?
            .unwrap_or(Value::Unit);
        if !values_equal(ctx, &left_value, &right_value, max_depth - 1)? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn normalize_existing_index(index: i64, len: usize) -> Result<usize, String> {
    let len_i64 = i64::try_from(len).map_err(|_| "list length exceeds i64 range".to_owned())?;
    let normalized = if index < 0 { len_i64 + index } else { index };
    if normalized < 0 || normalized >= len_i64 {
        return Err("list index out of range".to_owned());
    }
    usize::try_from(normalized).map_err(|_| "list index is too large".to_owned())
}

fn normalize_insert_index(index: i64, len: usize) -> usize {
    let Ok(len_i64) = i64::try_from(len) else {
        return len;
    };
    let normalized = if index < 0 { len_i64 + index } else { index };
    if normalized <= 0 {
        0
    } else if normalized >= len_i64 {
        len
    } else {
        usize::try_from(normalized).unwrap_or(len)
    }
}

fn normalize_search_bounds(
    start: Option<Value>,
    stop: Option<Value>,
    len: usize,
) -> Result<(usize, usize), String> {
    let len_i = i128::try_from(len).map_err(|_| "list length exceeds i128 range".to_owned())?;
    let normalize = |value: Option<Value>, default: i128| -> Result<usize, String> {
        let raw = match value {
            Some(value) => value_to_signed_index(&value, "index bound")?,
            None => default,
        };
        let normalized = if raw < 0 { raw + len_i } else { raw }.clamp(0, len_i);
        usize::try_from(normalized).map_err(|_| "index bound is too large".to_owned())
    };

    let start = normalize(start, 0)?;
    let stop = normalize(stop, len_i)?;
    Ok((start, stop.max(start)))
}

fn stepped_range_len(start: i64, stop: i64, step: i64) -> Result<usize, String> {
    let start = i128::from(start);
    let stop = i128::from(stop);
    let step = i128::from(step);

    let count = if step > 0 {
        if start >= stop {
            0
        } else {
            ((stop - start - 1) / step) + 1
        }
    } else if start <= stop {
        0
    } else {
        ((start - stop - 1) / -step) + 1
    };

    usize::try_from(count).map_err(|_| "range length is too large".to_owned())
}

fn sort_values(values: &mut [Value]) -> Result<(), String> {
    for index in 1..values.len() {
        let mut current = index;
        while current > 0
            && compare_sort_values(&values[current], &values[current - 1])? == Ordering::Less
        {
            values.swap(current, current - 1);
            current -= 1;
        }
    }
    Ok(())
}

fn compare_sort_values(left: &Value, right: &Value) -> Result<Ordering, String> {
    if let (Some(left), Some(right)) = (numeric_sort_value(left), numeric_sort_value(right)) {
        return compare_numeric_sort_values(left, right);
    }

    match (left, right) {
        (Value::String(left), Value::String(right)) => Ok(left.cmp(right)),
        (Value::Bool(left), Value::Bool(right)) => Ok(left.cmp(right)),
        _ => Err(format!(
            "list sort does not support comparing {} and {}",
            left.type_name(),
            right.type_name()
        )),
    }
}

#[derive(Clone, Copy)]
enum NumericSortValue {
    Signed(i128),
    Unsigned(u128),
    Float(f64),
}

fn numeric_sort_value(value: &Value) -> Option<NumericSortValue> {
    match value {
        Value::I64(value) => Some(NumericSortValue::Signed((*value).into())),
        Value::I32(value) => Some(NumericSortValue::Signed((*value).into())),
        Value::I16(value) => Some(NumericSortValue::Signed((*value).into())),
        Value::I8(value) => Some(NumericSortValue::Signed((*value).into())),
        Value::U64(value) => Some(NumericSortValue::Unsigned((*value).into())),
        Value::U32(value) => Some(NumericSortValue::Unsigned((*value).into())),
        Value::U16(value) => Some(NumericSortValue::Unsigned((*value).into())),
        Value::U8(value) => Some(NumericSortValue::Unsigned((*value).into())),
        Value::Float(value) => Some(NumericSortValue::Float(value.0)),
        _ => None,
    }
}

fn compare_numeric_sort_values(
    left: NumericSortValue,
    right: NumericSortValue,
) -> Result<Ordering, String> {
    match (left, right) {
        (NumericSortValue::Signed(left), NumericSortValue::Signed(right)) => Ok(left.cmp(&right)),
        (NumericSortValue::Unsigned(left), NumericSortValue::Unsigned(right)) => {
            Ok(left.cmp(&right))
        }
        (NumericSortValue::Signed(left), NumericSortValue::Unsigned(right)) => {
            if left < 0 {
                Ok(Ordering::Less)
            } else {
                Ok((left as u128).cmp(&right))
            }
        }
        (NumericSortValue::Unsigned(left), NumericSortValue::Signed(right)) => {
            if right < 0 {
                Ok(Ordering::Greater)
            } else {
                Ok(left.cmp(&(right as u128)))
            }
        }
        (left, right) => numeric_sort_value_as_f64(left)
            .partial_cmp(&numeric_sort_value_as_f64(right))
            .ok_or_else(|| "list sort does not support NaN values".to_owned()),
    }
}

fn numeric_sort_value_as_f64(value: NumericSortValue) -> f64 {
    match value {
        NumericSortValue::Signed(value) => value as f64,
        NumericSortValue::Unsigned(value) => value as f64,
        NumericSortValue::Float(value) => value,
    }
}

fn format_print_array(
    ctx: &mut ForeignFunctionContext<'_>,
    array_ref: stoffel_vm_types::core_types::ArrayRef,
    max_depth: usize,
    active_tables: &mut HashSet<TableRef>,
) -> ForeignFunctionCallbackResult<String> {
    let len = ctx.read_array_ref_len(array_ref)?;
    if max_depth == 0 {
        return Ok(format!("[...{} elements]", len));
    }

    let display_count = len.min(16);
    let mut parts = Vec::with_capacity(display_count);
    for index in 0..display_count {
        let value = ctx
            .read_table_field(TableRef::from(array_ref), &Value::I64(index as i64))?
            .unwrap_or(Value::Unit);
        parts.push(format_print_value(
            ctx,
            &value,
            max_depth - 1,
            active_tables,
        )?);
    }

    if len > display_count {
        parts.push(format!("...({} more)", len - display_count));
    }
    Ok(format!("[{}]", parts.join(", ")))
}

fn format_print_object(
    ctx: &mut ForeignFunctionContext<'_>,
    object_ref: stoffel_vm_types::core_types::ObjectRef,
    max_depth: usize,
    active_tables: &mut HashSet<TableRef>,
) -> ForeignFunctionCallbackResult<String> {
    let len = ctx.read_object_ref_len(object_ref)?;
    if max_depth == 0 {
        return Ok(format!("{{...{} fields}}", len));
    }

    let entries = ctx.read_object_ref_entries(object_ref, 16)?;
    let truncated = len > entries.len();
    let mut parts = Vec::with_capacity(entries.len() + usize::from(truncated));
    for (key, value) in entries {
        let key = match key {
            Value::String(key) => key,
            key => format_print_value(ctx, &key, 0, active_tables)?,
        };
        let value = format_print_value(ctx, &value, max_depth - 1, active_tables)?;
        parts.push(format!("{key}: {value}"));
    }

    if truncated {
        parts.push(format!("...({} more)", len - parts.len()));
    }
    Ok(format!("{{{}}}", parts.join(", ")))
}

pub(crate) fn encode_output_share_list(shares: &[ShareData]) -> Result<Vec<u8>, String> {
    if shares.len() > u32::MAX as usize {
        return Err("Too many output shares to send to client".to_owned());
    }

    let payload_len = shares.iter().try_fold(
        OUTPUT_SHARE_LIST_MAGIC.len() + std::mem::size_of::<u32>(),
        |acc, share| {
            let len = share.as_bytes().len();
            if len > u32::MAX as usize {
                return Err("Output share is too large to send to client".to_owned());
            }
            acc.checked_add(std::mem::size_of::<u32>())
                .and_then(|value| value.checked_add(len))
                .ok_or_else(|| "Output share payload is too large".to_owned())
        },
    )?;

    let mut payload = Vec::with_capacity(payload_len);
    payload.extend_from_slice(OUTPUT_SHARE_LIST_MAGIC);
    payload.extend_from_slice(&(shares.len() as u32).to_le_bytes());
    for share in shares {
        let bytes = share.as_bytes();
        payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(bytes);
    }
    Ok(payload)
}

fn local_storage_key(
    ctx: &mut ForeignFunctionContext<'_>,
    key_value: Value,
) -> ForeignFunctionCallbackResult<Vec<u8>> {
    match key_value {
        Value::String(key) => Ok(key.into_bytes()),
        key_value => ctx.read_byte_array(&key_value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::curve::{MpcCurveConfig, MpcFieldKind};
    use crate::net::mpc_engine::{
        MpcCapabilities, MpcEngine, MpcEngineClientOutput, MpcEngineError, MpcEngineResult,
        MpcSessionTopology,
    };
    use crate::output::{VmOutputResult, VmOutputSink};
    use crate::storage::RedbLocalStorage;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use stoffel_vm_types::core_types::{ClearShareInput, ClearShareValue, ShareData};
    use stoffelnet::network_utils::ClientId;

    #[derive(Clone, Default)]
    struct RecordingOutputSink {
        lines: Arc<Mutex<Vec<String>>>,
    }

    impl VmOutputSink for RecordingOutputSink {
        fn write_line(&self, line: &str) -> VmOutputResult<()> {
            self.lines.lock().push(line.to_owned());
            Ok(())
        }
    }

    #[test]
    fn python_shaped_array_aliases_are_registered() {
        let mut vm = VirtualMachine::try_new().expect("vm with standard library");
        let array = vm
            .execute_with_args("create_array", &[])
            .expect("create array");

        assert_eq!(
            vm.execute_with_args("append", &[array.clone(), Value::I64(7)])
                .expect("append value"),
            Value::Unit
        );
        assert_eq!(
            vm.execute_with_args("len", &[array]).expect("array length"),
            Value::I64(1)
        );
    }

    #[test]
    fn range_builtin_returns_python_style_exclusive_array() {
        let mut vm = VirtualMachine::try_new().expect("vm with standard library");
        let result = vm
            .execute_with_args("range", &[Value::I64(2), Value::I64(5)])
            .expect("range array");

        assert_eq!(
            vm.execute_with_args("len", &[result])
                .expect("range length"),
            Value::I64(3)
        );
    }

    struct StorageTestEngine {
        instance_id: u64,
    }

    impl StorageTestEngine {
        const fn new(instance_id: u64) -> Self {
            Self { instance_id }
        }
    }

    impl MpcEngine for StorageTestEngine {
        fn protocol_name(&self) -> &'static str {
            "avss-mpc"
        }

        fn topology(&self) -> MpcSessionTopology {
            MpcSessionTopology::try_new(self.instance_id, 0, 5, 1).expect("valid topology")
        }

        fn is_ready(&self) -> bool {
            true
        }

        fn start(&self) -> MpcEngineResult<()> {
            Ok(())
        }

        fn input_share(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
            Err(MpcEngineError::operation_failed(
                "storage_test",
                "input_share is not used",
            ))
        }

        fn open_share(
            &self,
            _ty: ShareType,
            _share_bytes: &[u8],
        ) -> MpcEngineResult<ClearShareValue> {
            Err(MpcEngineError::operation_failed(
                "storage_test",
                "open_share is not used",
            ))
        }

        fn curve_config(&self) -> MpcCurveConfig {
            MpcCurveConfig::Bls12_381
        }

        fn field_kind(&self) -> MpcFieldKind {
            MpcFieldKind::Bls12_381Fr
        }
    }

    type RecordedClientOutputs = Arc<Mutex<Vec<(ClientId, Vec<u8>, ClientOutputShareCount)>>>;

    #[derive(Clone, Default)]
    struct OutputRecordingEngine {
        sent: RecordedClientOutputs,
    }

    impl MpcEngine for OutputRecordingEngine {
        fn protocol_name(&self) -> &'static str {
            "avss-mpc"
        }

        fn topology(&self) -> MpcSessionTopology {
            MpcSessionTopology::try_new(7, 0, 5, 1).expect("valid topology")
        }

        fn is_ready(&self) -> bool {
            true
        }

        fn start(&self) -> MpcEngineResult<()> {
            Ok(())
        }

        fn input_share(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
            Err(MpcEngineError::operation_failed(
                "output_recording",
                "input_share is not used",
            ))
        }

        fn open_share(
            &self,
            _ty: ShareType,
            _share_bytes: &[u8],
        ) -> MpcEngineResult<ClearShareValue> {
            Err(MpcEngineError::operation_failed(
                "output_recording",
                "open_share is not used",
            ))
        }

        fn curve_config(&self) -> MpcCurveConfig {
            MpcCurveConfig::Bls12_381
        }

        fn field_kind(&self) -> MpcFieldKind {
            MpcFieldKind::Bls12_381Fr
        }

        fn capabilities(&self) -> MpcCapabilities {
            MpcCapabilities::CLIENT_OUTPUT
        }

        fn as_client_output(&self) -> Option<&dyn MpcEngineClientOutput> {
            Some(self)
        }
    }

    impl MpcEngineClientOutput for OutputRecordingEngine {
        fn send_output_to_client(
            &self,
            client_id: ClientId,
            shares: &[u8],
            output_share_count: ClientOutputShareCount,
        ) -> MpcEngineResult<()> {
            self.sent
                .lock()
                .push((client_id, shares.to_vec(), output_share_count));
            Ok(())
        }
    }

    #[test]
    fn print_uses_configured_vm_output_sink() {
        let output_sink = RecordingOutputSink::default();
        let lines = Arc::clone(&output_sink.lines);
        let mut vm = VirtualMachine::builder()
            .with_output_sink(output_sink)
            .try_build()
            .expect("build VM");

        vm.execute_with_args(
            "print",
            &[Value::String("answer".to_owned()), Value::I64(42)],
        )
        .expect("print should write through output sink");

        assert_eq!(lines.lock().as_slice(), &["answer 42"]);
    }

    #[test]
    fn print_formats_arrays_and_objects() {
        let output_sink = RecordingOutputSink::default();
        let lines = Arc::clone(&output_sink.lines);
        let mut vm = VirtualMachine::builder()
            .with_output_sink(output_sink)
            .try_build()
            .expect("build VM");
        let object = vm.execute_with_args("create_object", &[]).expect("object");
        let array = vm.execute_with_args("create_array", &[]).expect("array");
        vm.execute_with_args("append", &[array.clone(), Value::I64(1)])
            .expect("append first");
        vm.execute_with_args("append", &[array.clone(), Value::I64(10)])
            .expect("append second");
        vm.execute_with_args(
            "set_field",
            &[object.clone(), Value::String("n".to_owned()), Value::I64(1)],
        )
        .expect("set n");
        vm.execute_with_args(
            "set_field",
            &[
                object.clone(),
                Value::String("coeffs".to_owned()),
                array.clone(),
            ],
        )
        .expect("set coeffs");

        vm.execute_with_args("print", &[object])
            .expect("print should write rich output");

        assert_eq!(lines.lock().as_slice(), &["{coeffs: [1, 10], n: 1}"]);
    }

    #[test]
    fn cloned_vm_preserves_configured_output_sink() {
        let output_sink = RecordingOutputSink::default();
        let lines = Arc::clone(&output_sink.lines);
        let vm = VirtualMachine::builder()
            .with_output_sink(output_sink)
            .try_build()
            .expect("build VM");
        let mut cloned = vm
            .try_clone_with_independent_state()
            .expect("clone VM with configured output sink");

        cloned
            .execute_with_args("print", &[Value::String("clone".to_owned())])
            .expect("print should use cloned VM output sink");

        assert_eq!(lines.lock().as_slice(), &["clone"]);
    }

    #[test]
    fn local_storage_builtins_persist_vm_values() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("local.redb");
        let stored = Value::Share(
            ShareType::secret_int(64),
            ShareData::Feldman {
                data: vec![1, 2, 3].into(),
                commitments: vec![vec![4, 5], vec![6]].into(),
            },
        );

        {
            let storage = RedbLocalStorage::new(&path).expect("open storage");
            let mut vm = VirtualMachine::builder()
                .with_local_storage(storage)
                .with_mpc_engine(Arc::new(StorageTestEngine::new(7)))
                .try_build()
                .expect("build VM");

            assert_eq!(
                vm.execute_with_args(
                    "LocalStorage.store",
                    &[Value::String("share".to_owned()), stored.clone()]
                )
                .expect("store value"),
                Value::Bool(true)
            );
            assert_eq!(
                vm.execute_with_args("LocalStorage.exists", &[Value::String("share".to_owned())])
                    .expect("exists"),
                Value::Bool(true)
            );

            let mut cloned = vm
                .try_clone_with_independent_state()
                .expect("clone VM with storage");
            assert_eq!(
                cloned
                    .execute_with_args("LocalStorage.load", &[Value::String("share".to_owned())])
                    .expect("load from clone"),
                stored.clone()
            );
        }

        let storage = RedbLocalStorage::new(&path).expect("reopen storage");
        let mut vm = VirtualMachine::builder()
            .with_local_storage(storage)
            .with_mpc_engine(Arc::new(StorageTestEngine::new(99)))
            .try_build()
            .expect("build VM");

        assert_eq!(
            vm.execute_with_args("LocalStorage.load", &[Value::String("share".to_owned())])
                .expect("load value"),
            stored
        );
        assert_eq!(
            vm.execute_with_args("LocalStorage.delete", &[Value::String("share".to_owned())])
                .expect("delete value"),
            Value::Bool(true)
        );
        assert_eq!(
            vm.execute_with_args(
                "LocalStorage.retrieve",
                &[Value::String("share".to_owned())]
            )
            .expect("load missing"),
            Value::Unit
        );
    }

    #[test]
    fn strings_can_be_read_with_collection_builtins() {
        let mut vm = VirtualMachine::builder().try_build().expect("build VM");

        assert_eq!(
            vm.execute_with_args("array_length", &[Value::String("score".to_owned())])
                .expect("string length"),
            Value::I64(5)
        );
        assert_eq!(
            vm.execute_with_args(
                "get_field",
                &[Value::String("score".to_owned()), Value::I64(1)]
            )
            .expect("string index"),
            Value::String("c".to_owned())
        );
        let err = vm
            .execute_with_args(
                "get_field",
                &[Value::String("score".to_owned()), Value::I64(99)],
            )
            .expect_err("out of bounds string index should error");
        assert!(
            err.to_string().contains("out of range"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn mpc_output_array_sends_bounded_share_list_envelope() {
        let engine = OutputRecordingEngine::default();
        let sent = Arc::clone(&engine.sent);
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(Arc::new(engine))
            .try_build()
            .expect("build VM");

        let output_array = vm
            .execute_with_args("create_array", &[Value::I64(2)])
            .expect("create output array");
        let first = Value::Share(
            ShareType::secret_int(64),
            ShareData::Opaque(vec![1, 2, 3].into()),
        );
        let second = Value::Share(
            ShareType::secret_int(64),
            ShareData::Opaque(vec![4, 5].into()),
        );

        vm.execute_with_args("array_push", &[output_array.clone(), first])
            .expect("push first output share");
        vm.execute_with_args("array_push", &[output_array.clone(), second])
            .expect("push second output share");

        assert_eq!(
            vm.execute_with_args("MpcOutput.send_to_client", &[Value::I64(7), output_array])
                .expect("send output shares"),
            Value::Bool(true)
        );

        let sent = sent.lock();
        assert_eq!(sent.len(), 1);
        let (client_id, payload, count) = &sent[0];
        assert_eq!(*client_id, 7);
        assert_eq!(count.count(), 2);

        let mut offset = OUTPUT_SHARE_LIST_MAGIC.len();
        assert_eq!(&payload[..offset], OUTPUT_SHARE_LIST_MAGIC);
        assert_eq!(read_test_u32(payload, &mut offset), 2);
        assert_eq!(read_test_vec(payload, &mut offset), vec![1, 2, 3]);
        assert_eq!(read_test_vec(payload, &mut offset), vec![4, 5]);
        assert_eq!(offset, payload.len());
    }

    fn read_test_u32(bytes: &[u8], offset: &mut usize) -> u32 {
        let end = *offset + std::mem::size_of::<u32>();
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&bytes[*offset..end]);
        *offset = end;
        u32::from_le_bytes(raw)
    }

    fn read_test_vec(bytes: &[u8], offset: &mut usize) -> Vec<u8> {
        let len = read_test_u32(bytes, offset) as usize;
        let end = *offset + len;
        let value = bytes[*offset..end].to_vec();
        *offset = end;
        value
    }
}
