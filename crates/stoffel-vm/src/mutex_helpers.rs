use parking_lot::Mutex;

/// Helper function to fix the parking_lot::Mutex lock() usage.
/// This function removes the need for `if let Ok(...)` pattern when using parking_lot::Mutex.
pub fn lock_mutex<T>(mutex: &Mutex<T>) -> parking_lot::MutexGuard<'_, T> {
    mutex.lock()
}

/// Helper function to make parking_lot::Mutex lock() return a Result to be compatible with std::sync::Mutex.
/// This allows code that was written for std::sync::Mutex to work with parking_lot::Mutex.
pub fn lock_mutex_as_result<T>(mutex: &Mutex<T>) -> Result<parking_lot::MutexGuard<'_, T>, ()> {
    Ok(mutex.lock())
}
