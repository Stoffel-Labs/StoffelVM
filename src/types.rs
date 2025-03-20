use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

/// Represents an array in the VM
#[derive(Debug, Clone)]
pub struct Array {
    elements: Vec<Value>,
    extra_fields: HashMap<Value, Value>, // For non-integer or sparse indices
}

impl Default for Array {
    fn default() -> Self {
        Self::new()
    }
}

impl Array {
    pub fn new() -> Self {
        Array {
            elements: Vec::new(),
            extra_fields: HashMap::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Array {
            elements: Vec::with_capacity(capacity),
            extra_fields: HashMap::new(),
        }
    }

    pub fn get(&self, key: &Value) -> Option<&Value> {
        match key {
            Value::Int(idx) if *idx >= 1 && (*idx as usize) <= self.elements.len() => {
                Some(&self.elements[*idx as usize - 1])
            },
            _ => self.extra_fields.get(key),
        }
    }

    pub fn set(&mut self, key: Value, value: Value) {
        match key {
            Value::Int(idx) if idx >= 1 => {
                let idx_usize = idx as usize - 1;

                if idx_usize == self.elements.len() {
                    self.elements.push(value);
                    return;
                }

                if idx_usize < self.elements.len() {
                    self.elements[idx_usize] = value;
                    return;
                }

                if idx_usize < self.elements.len() + 16 {
                    self.elements.resize(idx_usize + 1, Value::Unit);
                    self.elements[idx_usize] = value;
                    return;
                }

                self.extra_fields.insert(Value::Int(idx), value);
            },
            _ => {
                self.extra_fields.insert(key, value);
            }
        }
    }

    pub fn length(&self) -> usize {
        self.elements.len()
    }
}

/// Represents an upvalue - a variable from an outer scope
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Upvalue {
    pub name: String,
    pub value: Value,
}

/// Represents a closure - a function with its captured environment
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Closure {
    pub function_id: String,    // Reference to the base function
    pub upvalues: Vec<Upvalue>, // Captured values from outer scopes
}

/// Value types supported by the VM
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Value {
    Int(i64),
    Float(i64),  // Represented as fixed-point for Eq/Hash
    Bool(bool),
    String(String),
    Object(usize),    // Regular object reference
    Array(usize),     // Array reference
    Foreign(usize),   // External object reference
    Closure(Arc<Closure>), // Function closure
    Unit,
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Int(i) => write!(f, "{}", i),
            Value::Float(fp) => {
                let float_val = *fp as f64 / 1000.0;
                write!(f, "{}", float_val)
            },
            Value::Bool(b) => write!(f, "{}", b),
            Value::String(s) => write!(f, "\"{}\"", s),
            Value::Object(id) => write!(f, "Object({})", id),
            Value::Array(id) => write!(f, "Array({})", id),
            Value::Foreign(id) => write!(f, "Foreign({})", id),
            Value::Closure(c) => write!(f, "Function({})", c.function_id),
            Value::Unit => write!(f, "()"),
        }
    }
}

/// Object structure
#[derive(Debug, Clone)]
pub struct Object {
    pub fields: HashMap<Value, Value>,
}

/// Combined object/array storage
#[derive(Default)]
pub struct ObjectStore {
    pub objects: HashMap<usize, Object>,
    pub arrays: HashMap<usize, Array>,
    pub next_id: usize,
}

impl ObjectStore {
    pub fn new() -> Self {
        ObjectStore {
            objects: HashMap::new(),
            arrays: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn create_object(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.objects.insert(id, Object {
            fields: HashMap::new(),
        });
        id
    }

    pub fn create_array(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.arrays.insert(id, Array::new());
        id
    }

    pub fn create_array_with_capacity(&mut self, capacity: usize) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.arrays.insert(id, Array::with_capacity(capacity));
        id
    }

    pub fn get_object(&self, id: usize) -> Option<&Object> {
        self.objects.get(&id)
    }

    pub fn get_object_mut(&mut self, id: usize) -> Option<&mut Object> {
        self.objects.get_mut(&id)
    }

    pub fn get_array(&self, id: usize) -> Option<&Array> {
        self.arrays.get(&id)
    }

    pub fn get_array_mut(&mut self, id: usize) -> Option<&mut Array> {
        self.arrays.get_mut(&id)
    }

    pub fn get_field(&self, value: &Value, key: &Value) -> Option<Value> {
        match value {
            Value::Object(id) => {
                self.get_object(*id).and_then(|obj| obj.fields.get(key).cloned())
            },
            Value::Array(id) => {
                self.get_array(*id).and_then(|arr| arr.get(key).cloned())
            },
            _ => None
        }
    }

    pub fn set_field(&mut self, value: &Value, key: Value, field_value: Value) -> Result<(), String> {
        match value {
            Value::Object(id) => {
                if let Some(obj) = self.get_object_mut(*id) {
                    obj.fields.insert(key, field_value);
                    Ok(())
                } else {
                    Err(format!("Object with ID {} not found", id))
                }
            },
            Value::Array(id) => {
                if let Some(arr) = self.get_array_mut(*id) {
                    arr.set(key, field_value);
                    Ok(())
                } else {
                    Err(format!("Array with ID {} not found", id))
                }
            },
            _ => Err("Expected object or array".to_string())
        }
    }
}

/// Trait for type-erased objects
pub trait AnyObject: Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Type-specific container implementing AnyObject
pub struct TypedObject<T: 'static + Send + Sync> {
    pub value: Arc<Mutex<T>>
}

impl<T: 'static + Send + Sync> AnyObject for TypedObject<T> {
    fn as_any(&self) -> &dyn Any { self }
    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

/// Foreign object storage
pub struct ForeignObjectStorage {
    pub objects: HashMap<usize, Box<dyn AnyObject + Send + Sync>>,
    pub next_id: usize,
}

impl Default for ForeignObjectStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl ForeignObjectStorage {
    pub fn new() -> Self {
        ForeignObjectStorage {
            objects: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn register_object<T: 'static + Send + Sync>(&mut self, object: T) -> usize {
        let id = self.next_id;
        self.next_id += 1;

        // Store a TypedObject wrapper that preserves the exact type
        let typed_obj = TypedObject {
            value: Arc::new(Mutex::new(object))
        };
        self.objects.insert(id, Box::new(typed_obj));

        id
    }

    pub fn get_object<T: 'static + Send + Sync>(&self, id: usize) -> Option<Arc<Mutex<T>>> {
        self.objects.get(&id).and_then(|obj| {
            // Using safe downcast
            if let Some(typed) = obj.as_any().downcast_ref::<TypedObject<T>>() {
                Some(Arc::clone(&typed.value))
            } else {
                None
            }
        })
    }
}