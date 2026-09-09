use super::format::ensure_homogeneous_share_data_format;
use super::MpcShareRuntime;
use crate::error::{MpcBackendResultExt, VmError, VmResult};
use crate::net::curve::clear_share_value_to_vm_value;
use crate::net::mpc_engine::MpcExponentGroup;
use stoffel_vm_types::core_types::{ClearShareValue, ShareData, ShareType, Value};

impl MpcShareRuntime<'_> {
    pub(crate) fn open_share_value(&self, value: &Value) -> VmResult<Value> {
        match value {
            Value::Share(
                ty @ (ShareType::SecretInt { .. } | ShareType::SecretUInt { .. }),
                share_data,
            )
            | Value::Share(ty @ ShareType::SecretFixedPoint { .. }, share_data) => Ok(
                clear_share_value_to_vm_value(*ty, self.open_share_data(*ty, share_data)?),
            ),
            _ => Err(VmError::InvalidShareRevealValue),
        }
    }

    pub(crate) fn open_share_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
    ) -> VmResult<ClearShareValue> {
        self.ensure_ready()?;
        self.engine
            .open_share(ty, share_data.as_bytes())
            .map_mpc_backend_err("open_share")
    }

    pub(crate) fn batch_open_share_data(
        &self,
        ty: ShareType,
        shares: &[ShareData],
    ) -> VmResult<Vec<ClearShareValue>> {
        self.ensure_ready()?;
        ensure_homogeneous_share_data_format("batch_open_shares", shares)?;
        let share_bytes: Vec<Vec<u8>> = shares
            .iter()
            .map(|share_data| share_data.as_bytes().to_vec())
            .collect();
        self.engine
            .batch_open_shares(ty, &share_bytes)
            .map_mpc_backend_err("batch_open_shares")
    }

    pub(crate) fn random_share_data(&self, ty: ShareType) -> VmResult<ShareData> {
        self.ensure_ready()?;
        self.engine
            .randomness_ops()
            .map_mpc_backend_err("randomness_ops")?
            .random_share(ty)
            .map_mpc_backend_err("random_share")
    }

    pub(crate) fn random_integer_share_data(&self, ty: ShareType) -> VmResult<ShareData> {
        self.ensure_ready()?;
        self.engine
            .randomness_ops()
            .map_mpc_backend_err("randomness_ops")?
            .random_integer_share(ty)
            .map_mpc_backend_err("random_integer_share")
    }

    pub(crate) fn open_share_as_field_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
    ) -> VmResult<Vec<u8>> {
        self.ensure_ready()?;
        self.engine
            .field_open_ops()
            .map_mpc_backend_err("field_open_ops")?
            .open_share_as_field(ty, share_data.as_bytes())
            .map_mpc_backend_err("open_share_as_field")
    }

    pub(crate) fn batch_open_shares_as_field_data(
        &self,
        ty: ShareType,
        shares: &[ShareData],
    ) -> VmResult<Vec<Vec<u8>>> {
        self.ensure_ready()?;
        ensure_homogeneous_share_data_format("batch_open_shares_as_fields", shares)?;
        let share_bytes = shares
            .iter()
            .map(|share| share.as_bytes().to_vec())
            .collect::<Vec<_>>();
        self.engine
            .field_open_ops()
            .map_mpc_backend_err("field_open_ops")?
            .batch_open_shares_as_fields(ty, &share_bytes)
            .map_mpc_backend_err("batch_open_shares_as_fields")
    }

    pub(crate) fn open_share_in_exp_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        generator_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        self.ensure_ready()?;
        self.engine
            .open_in_exp_ops()
            .map_mpc_backend_err("open_in_exp_ops")?
            .open_share_in_exp(ty, share_data.as_bytes(), generator_bytes)
            .map_mpc_backend_err("open_share_in_exp")
    }

    pub(crate) fn open_share_in_exp_group_data(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        share_data: &ShareData,
        generator_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        self.ensure_ready()?;
        self.engine
            .open_in_exp_ops()
            .map_mpc_backend_err("open_in_exp_ops")?
            .open_share_in_exp_group(group, ty, share_data.as_bytes(), generator_bytes)
            .map_mpc_backend_err("open_share_in_exp_group")
    }

    pub(crate) fn batch_open_shares_in_exp_group_data(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        shares: &[ShareData],
        generator_bytes: &[u8],
    ) -> VmResult<Vec<Vec<u8>>> {
        self.ensure_ready()?;
        ensure_homogeneous_share_data_format("batch_open_shares_in_exp_group", shares)?;
        let share_bytes = shares
            .iter()
            .map(|share| share.as_bytes().to_vec())
            .collect::<Vec<_>>();
        self.engine
            .open_in_exp_ops()
            .map_mpc_backend_err("open_in_exp_ops")?
            .batch_open_shares_in_exp_group(group, ty, &share_bytes, generator_bytes)
            .map_mpc_backend_err("batch_open_shares_in_exp_group")
    }

    pub(crate) fn batch_open_shares_in_exp_group_custom_data(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        shares: &[ShareData],
        generators: &[Vec<u8>],
    ) -> VmResult<Vec<Vec<u8>>> {
        self.ensure_ready()?;
        ensure_homogeneous_share_data_format("batch_open_shares_in_exp_group_custom", shares)?;
        let share_bytes = shares
            .iter()
            .map(|share| share.as_bytes().to_vec())
            .collect::<Vec<_>>();
        self.engine
            .open_in_exp_ops()
            .map_mpc_backend_err("open_in_exp_ops")?
            .batch_open_shares_in_exp_group_custom(group, ty, &share_bytes, generators)
            .map_mpc_backend_err("batch_open_shares_in_exp_group_custom")
    }
}
