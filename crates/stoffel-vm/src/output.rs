use std::io::{self, Write};

pub type VmOutputResult<T> = Result<T, VmOutputError>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VmOutputError {
    #[error("{0}")]
    Message(String),
    #[error("VM output write failed: {reason}")]
    Io { reason: String },
}

impl From<io::Error> for VmOutputError {
    fn from(error: io::Error) -> Self {
        Self::Io {
            reason: error.to_string(),
        }
    }
}

impl From<String> for VmOutputError {
    fn from(message: String) -> Self {
        Self::Message(message)
    }
}

impl From<&str> for VmOutputError {
    fn from(message: &str) -> Self {
        Self::Message(message.to_owned())
    }
}

impl From<VmOutputError> for String {
    fn from(error: VmOutputError) -> Self {
        error.to_string()
    }
}

pub trait VmOutputSink: Send + Sync {
    fn write_line(&self, line: &str) -> VmOutputResult<()>;
}

#[derive(Debug, Default)]
pub struct StdoutOutputSink;

impl VmOutputSink for StdoutOutputSink {
    fn write_line(&self, line: &str) -> VmOutputResult<()> {
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{line}")?;
        Ok(())
    }
}
