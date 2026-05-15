use crate::core_vm::VirtualMachine;
use crate::net::client_store::{ClientInputIndex, ClientOutputShareCount, ClientShareIndex};
use crate::runtime_hooks::HookEvent;
use crate::value_conversions::{usize_to_vm_i64, value_to_usize};
use crate::VirtualMachineResult;
use stoffel_vm_types::core_types::{ShareType, TableRef, Value};

pub(crate) const FUNCTION_NAMES: &[&str] = &[
    "create_object",
    "create_array",
    "get_field",
    "set_field",
    "array_length",
    "array_push",
    "ClientStore.get_number_clients",
    "ClientStore.take_share",
    "ClientStore.take_share_fixed",
    "MpcOutput.send_to_client",
    "create_closure",
    "call_closure",
    "get_upvalue",
    "set_upvalue",
    "print",
    "type",
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
            let Some(table_ref) = TableRef::from_value(&target) else {
                return Ok(Value::Unit);
            };
            (table_ref, args.cloned(1)?)
        };

        let value = ctx
            .read_table_field(table_ref, &key)?
            .unwrap_or(Value::Unit);

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

        Ok(value)
    });

    register_standard_builtin!("set_field", |mut ctx| {
        let (target, key, new_value) = {
            let args = ctx.named_args("set_field");
            args.require_min(3, "3 arguments: object, key, and value")?;
            (args.cloned(0)?, args.cloned(1)?, args.cloned(2)?)
        };

        let table_ref = TableRef::try_from(&target)?;
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
        let array_ref = {
            let args = ctx.named_args("array_length");
            args.require_exact(1, "1 argument: array")?;
            args.array_ref(0, "First argument")?
        };

        let len = ctx.read_array_ref_len(array_ref)?;
        let len = usize_to_vm_i64(len, "array length")?;
        Ok(Value::I64(len))
    });

    register_standard_builtin!("array_push", |mut ctx| {
        let (array_ref, values) = {
            let args = ctx.named_args("array_push");
            args.require_min(2, "at least 2 arguments: array and value")?;
            let array_ref = args.array_ref(0, "First argument")?;
            (array_ref, args.tail_from(1)?.to_vec())
        };

        let len = ctx.push_array_ref_values(array_ref, &values)?;
        Ok(Value::I64(usize_to_vm_i64(len, "array length")?))
    });

    register_standard_builtin!("ClientStore.get_number_clients", |ctx| {
        let count = ctx.client_store_len();
        Ok(Value::I64(usize_to_vm_i64(count, "client count")?))
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

    register_standard_builtin!("ClientStore.take_share_fixed", |ctx| {
        let args = ctx.named_args("ClientStore.take_share_fixed");
        args.require_exact(2, "2 arguments: client_index, share_index")?;

        let client_index = ClientInputIndex::new(args.usize(0, "client_index")?);
        let share_index = ClientShareIndex::new(args.usize(1, "share_index")?);

        let client_id = ctx
            .client_id_at_index(client_index)
            .ok_or_else(|| format!("No client at index {}", client_index))?;

        Ok(ctx.load_client_share_as(
            client_id,
            share_index,
            ShareType::default_secret_fixed_point(),
        )?)
    });

    register_standard_builtin!("MpcOutput.send_to_client", |mut ctx| {
        let (client_id, share_value) = {
            let args = ctx.named_args("MpcOutput.send_to_client");
            args.require_exact(2, "2 arguments: client_id, share_value")?;
            (args.usize(0, "client_id")?, args.cloned(1)?)
        };

        let (_share_type, share_data) = ctx.extract_share_data(&share_value)?;
        let share_bytes = share_data.as_bytes().to_vec();

        ctx.send_output_to_client(client_id, &share_bytes, ClientOutputShareCount::one())?;

        Ok(Value::Bool(true))
    });

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

    register_standard_builtin!("print", |ctx| {
        let args = ctx.args();
        let mut output = String::new();
        for (i, arg) in args.iter().enumerate() {
            if i > 0 {
                output.push(' ');
            }
            match arg {
                Value::String(s) => output.push_str(s),
                _ => output.push_str(&format!("{:?}", arg)),
            }
        }
        ctx.write_output_line(&output)?;
        Ok(Value::Unit)
    });

    register_standard_builtin!("type", |ctx| {
        let args = ctx.named_args("type");
        args.require_exact(1, "1 argument")?;

        Ok(Value::String(args.get(0)?.type_name().to_string()))
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{VmOutputResult, VmOutputSink};
    use parking_lot::Mutex;
    use std::sync::Arc;

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
}
