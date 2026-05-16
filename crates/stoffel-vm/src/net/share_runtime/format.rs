use crate::error::{VmError, VmResult};
use stoffel_vm_types::core_types::ShareData;

pub(crate) fn ensure_matching_share_data_format(
    operation: &'static str,
    left: &ShareData,
    right: &ShareData,
) -> VmResult<()> {
    let left = left.format();
    let right = right.format();
    if left == right {
        Ok(())
    } else {
        Err(VmError::ShareDataFormatMismatch {
            operation,
            left: left.as_str(),
            right: right.as_str(),
        })
    }
}

pub(super) fn ensure_homogeneous_share_data_format(
    operation: &'static str,
    shares: &[ShareData],
) -> VmResult<()> {
    let Some((first, rest)) = shares.split_first() else {
        return Ok(());
    };
    let expected = first.format();
    for (offset, share) in rest.iter().enumerate() {
        let actual = share.format();
        if actual != expected {
            return Err(VmError::ShareDataBatchFormatMismatch {
                operation,
                expected: expected.as_str(),
                actual: actual.as_str(),
                index: offset + 1,
            });
        }
    }
    Ok(())
}
