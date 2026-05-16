use super::format::{ensure_homogeneous_share_data_format, ensure_matching_share_data_format};
use super::MpcShareRuntime;
use crate::error::{MpcBackendResultExt, VmResult};
use crate::net::share_algebra;
use stoffel_vm_types::core_types::{ShareData, ShareType, Value};

impl MpcShareRuntime<'_> {
    pub(crate) fn multiply_share_data(
        &self,
        share_type: ShareType,
        left_data: &ShareData,
        right_data: &ShareData,
    ) -> VmResult<ShareData> {
        self.ensure_ready()?;
        ensure_matching_share_data_format("multiply_share", left_data, right_data)?;
        self.engine
            .multiplication_ops()
            .map_mpc_backend_err("multiplication_ops")?
            .multiply_share(share_type, left_data.as_bytes(), right_data.as_bytes())
            .map_mpc_backend_err("multiply_share")
    }

    pub(crate) fn add_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData> {
        ensure_matching_share_data_format("add_share_local", lhs_data, rhs_data)?;
        let result = self
            .engine
            .add_share_local(ty, lhs_data.as_bytes(), rhs_data.as_bytes())
            .map_mpc_backend_err("add_share_local")?;
        self.preserve_share_data_format(lhs_data, result)
    }

    pub(crate) fn sub_data(
        &self,
        ty: ShareType,
        lhs_data: &ShareData,
        rhs_data: &ShareData,
    ) -> VmResult<ShareData> {
        ensure_matching_share_data_format("sub_share_local", lhs_data, rhs_data)?;
        let result = self
            .engine
            .sub_share_local(ty, lhs_data.as_bytes(), rhs_data.as_bytes())
            .map_mpc_backend_err("sub_share_local")?;
        self.preserve_share_data_format(lhs_data, result)
    }

    pub(crate) fn neg_data(&self, ty: ShareType, share_data: &ShareData) -> VmResult<ShareData> {
        let result = self
            .engine
            .neg_share_local(ty, share_data.as_bytes())
            .map_mpc_backend_err("neg_share_local")?;
        self.preserve_share_data_format(share_data, result)
    }

    pub(crate) fn add_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData> {
        let result = self
            .engine
            .add_share_scalar_local(ty, share_data.as_bytes(), scalar)
            .map_mpc_backend_err("add_share_scalar_local")?;
        self.preserve_share_data_format(share_data, result)
    }

    pub(crate) fn sub_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData> {
        let result = self
            .engine
            .sub_share_scalar_local(ty, share_data.as_bytes(), scalar)
            .map_mpc_backend_err("sub_share_scalar_local")?;
        self.preserve_share_data_format(share_data, result)
    }

    pub(crate) fn scalar_sub_data(
        &self,
        ty: ShareType,
        scalar: i64,
        share_data: &ShareData,
    ) -> VmResult<ShareData> {
        let result = self
            .engine
            .scalar_sub_share_local(ty, scalar, share_data.as_bytes())
            .map_mpc_backend_err("scalar_sub_share_local")?;
        self.preserve_share_data_format(share_data, result)
    }

    pub(crate) fn div_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData> {
        let result = self
            .engine
            .div_share_scalar_local(ty, share_data.as_bytes(), scalar)
            .map_mpc_backend_err("div_share_scalar_local")?;
        self.preserve_share_data_format(share_data, result)
    }

    pub(crate) fn mul_scalar_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar: i64,
    ) -> VmResult<ShareData> {
        let result = self
            .engine
            .mul_share_scalar_local(ty, share_data.as_bytes(), scalar)
            .map_mpc_backend_err("mul_share_scalar_local")?;
        self.preserve_share_data_format(share_data, result)
    }

    pub(crate) fn mul_field_data(
        &self,
        ty: ShareType,
        share_data: &ShareData,
        scalar_bytes: &[u8],
    ) -> VmResult<ShareData> {
        let result = self
            .engine
            .mul_share_field_local(ty, share_data.as_bytes(), scalar_bytes)
            .map_mpc_backend_err("mul_share_field_local")?;
        self.preserve_share_data_format(share_data, result)
    }

    #[cfg(test)]
    pub(crate) fn add_bytes(
        &self,
        ty: ShareType,
        lhs_bytes: &[u8],
        rhs_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        self.engine
            .add_share_local(ty, lhs_bytes, rhs_bytes)
            .map_mpc_backend_err("add_share_local")
    }

    #[cfg(test)]
    pub(crate) fn add_scalar_bytes(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> VmResult<Vec<u8>> {
        self.engine
            .add_share_scalar_local(ty, share_bytes, scalar)
            .map_mpc_backend_err("add_share_scalar_local")
    }

    #[cfg(test)]
    pub(crate) fn sub_scalar_bytes(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> VmResult<Vec<u8>> {
        self.engine
            .sub_share_scalar_local(ty, share_bytes, scalar)
            .map_mpc_backend_err("sub_share_scalar_local")
    }

    #[cfg(test)]
    pub(crate) fn scalar_sub_bytes(
        &self,
        ty: ShareType,
        scalar: i64,
        share_bytes: &[u8],
    ) -> VmResult<Vec<u8>> {
        self.engine
            .scalar_sub_share_local(ty, scalar, share_bytes)
            .map_mpc_backend_err("scalar_sub_share_local")
    }

    pub(crate) fn interpolate_share_data_local(
        &self,
        ty: ShareType,
        shares: &[ShareData],
    ) -> VmResult<Value> {
        self.ensure_ready()?;
        ensure_homogeneous_share_data_format("interpolate_shares_local", shares)?;
        let share_bytes: Vec<Vec<u8>> = shares
            .iter()
            .map(|share_data| share_data.as_bytes().to_vec())
            .collect();
        self.interpolate_bytes_local(ty, &share_bytes)
    }

    fn interpolate_bytes_local(&self, ty: ShareType, shares: &[Vec<u8>]) -> VmResult<Value> {
        self.engine
            .interpolate_shares_local(ty, shares)
            .map_mpc_backend_err("interpolate_shares_local")
    }

    fn preserve_share_data_format(
        &self,
        template: &ShareData,
        result_bytes: Vec<u8>,
    ) -> VmResult<ShareData> {
        share_algebra::preserve_share_data_format(self.engine.field_kind(), template, result_bytes)
            .map_mpc_backend_err("preserve_share_data_format")
    }
}
