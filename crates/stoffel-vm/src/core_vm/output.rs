use super::VirtualMachine;
use crate::output::VmOutputSink;
use std::sync::Arc;

impl VirtualMachine {
    pub fn set_output_sink(&mut self, output_sink: Arc<dyn VmOutputSink>) {
        self.state.set_output_sink(output_sink);
    }

    pub fn output_sink(&self) -> Arc<dyn VmOutputSink> {
        self.state.output_sink()
    }
}
