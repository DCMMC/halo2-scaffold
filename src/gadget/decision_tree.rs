use halo2_base::{
    utils::{BigPrimeField, fe_to_biguint},
    Context, AssignedValue, gates::{GateInstructions, RangeInstructions}, QuantumCell
};
use num_bigint::BigUint;
use super::fixed_point::{FixedPointChip, FixedPointInstructions};
use halo2_base::QuantumCell::Constant;

const PRECISION_BITS: u32 = 63;

#[derive(Clone, Debug)]
pub struct DecisionTreeChip<F: BigPrimeField> {
    pub chip: FixedPointChip<F, 63>,
    pub lookup_bits: usize,
}

impl<F: BigPrimeField> DecisionTreeChip<F> {
    pub fn new(lookup_bits: usize) -> Self {
        let chip = FixedPointChip::<F, PRECISION_BITS>::default(lookup_bits);

        Self { chip, lookup_bits }
    }

    pub fn inference(
        &self,
        ctx: &mut Context<F>,
        tree: &[F],
        x: &[F],
        max_path_len: usize
    ) -> AssignedValue<F>
    where 
        F: BigPrimeField
    {
        // format of tree: [[data_slot, split, left_index, right_index, cls], ...]
        let zero = Constant(F::zero());
        let mut node_idx = self.chip.gate().add(ctx, zero, Constant(F::zero()));
        let mut x_advice = vec![];
        for xi in x {
            x_advice.push(ctx.load_witness(*xi));
        }
        for _ in 0..max_path_len {
            let node_offset = self.chip.gate().mul(ctx, node_idx, Constant(F::from(5)));
            let data_slot_idx = self.chip.gate().add(ctx, node_offset, Constant(F::from(0)));
            let data_slot = self.chip.gate().select_from_idx(
                ctx, tree.iter().cloned().map(Constant), data_slot_idx
            );
            let mut x_copy = vec![];
            for i in 0..x.len() {
                x_copy.push(ctx.load_witness(x[i]));
                // ensure copy works
                ctx.constrain_equal(x_copy.last().unwrap(), &x_advice[i]);
            }
            let data = self.chip.gate().select_from_idx(
                ctx, x_copy, data_slot);
            let split_idx = self.chip.gate().add(ctx, node_offset, Constant(F::from(1)));
            let split = self.chip.gate().select_from_idx(
                ctx, tree.iter().cloned().map(Constant), split_idx);
            let diff = self.chip.qsub(ctx, data, split);
            let is_less = self.chip.is_neg(ctx, diff);
            let left_idx_idx = self.chip.gate().add(ctx, node_offset, Constant(F::from(2)));
            let left_idx = self.chip.gate().select_from_idx(
                ctx, tree.iter().cloned().map(Constant), left_idx_idx);
            let right_idx_idx = self.chip.gate().add(ctx, node_offset, Constant(F::from(3)));
            let right_idx = self.chip.gate().select_from_idx(
                ctx, tree.iter().cloned().map(Constant), right_idx_idx);
            let next_idx = self.chip.gate().select(ctx, left_idx, right_idx, is_less);
            node_idx = next_idx;
        }
        let offset = self.chip.gate().mul(ctx, node_idx, Constant(F::from(5)));
        let cls_idx = self.chip.gate().add(ctx, offset, Constant(F::from(4)));
        let cls = self.chip.gate().select_from_idx(
            ctx, tree.iter().cloned().map(Constant), cls_idx);
        
        cls
    }

    fn copy_elem(
        &self,
        ctx: &mut Context<F>,
        elem: &AssignedValue<F>
    ) -> AssignedValue<F>
    {
        let x_copy = ctx.load_witness(*elem.value());
        ctx.constrain_equal(&x_copy, elem);

        x_copy
    }

    fn square(
        &self,
        ctx: &mut Context<F>,
        x: AssignedValue<F>
    ) -> AssignedValue<F>
    {
        // only support positive x (quantized)
        let x_square = self.chip.gate().mul(ctx, x, x);
        let scale = self.chip.quantization_scale;
        let num_bits = (2 * PRECISION_BITS + 1) as usize;
        let (res, _) = self.chip.range_gate().div_mod(ctx, x_square, fe_to_biguint(&scale), num_bits);

        res
    }

    pub fn gini(
        &self,
        ctx: &mut Context<F>,
        dataset_x: impl IntoIterator<Item = AssignedValue<F>>,
        dataset_y: impl IntoIterator<Item = AssignedValue<F>>,
        masks: impl IntoIterator<Item = AssignedValue<F>>,
        data_slot: usize,
        num_feature: usize,
        num_class: usize,
        split: AssignedValue<F>
    ) -> AssignedValue<F>
    where
        F: BigPrimeField
    {
        let mut num_group1: AssignedValue<F> = ctx.load_zero();
        let mut num_group2: AssignedValue<F> = ctx.load_zero();
        // ((x_ij, y_i), mask_i) where j is the data slot
        let targets = dataset_x.into_iter().skip(data_slot).step_by(num_feature).zip(
            dataset_y.into_iter()).zip(masks.into_iter());
        let one = Constant(F::one());
        let mut proportion_cls_grp1 = vec![ctx.load_zero(); num_class];
        let mut proportion_cls_grp2 = vec![ctx.load_zero(); num_class];
        let mut cls_adv = vec![];
        for cls_i in 0..num_class {
            cls_adv.push(ctx.load_constant(F::from(cls_i as u64)));
        }
        let mut cnt = 0;
        for ((x_ij, y_i), mask_i) in targets {
            cnt += 1;
            let diff = self.chip.qsub(ctx, x_ij, split);
            let is_less = self.chip.is_neg(ctx, diff);
            let mask_i_copy = self.copy_elem(ctx, &mask_i);
            let is_less_mask = self.chip.gate().mul(ctx, is_less, mask_i);
            num_group1 = self.chip.gate().add(ctx, num_group1, is_less_mask);
            let is_greater = self.chip.gate().sub(ctx, one, is_less);
            let is_geater_mask = self.chip.gate().mul(ctx, is_greater, mask_i_copy);
            num_group2 = self.chip.gate().add(ctx, num_group2, is_geater_mask);
            for cls_i in 0..num_class {
                let y_i_copy = self.copy_elem(ctx, &y_i);
                let is_cls_i = self.chip.gate().is_equal(ctx, y_i_copy, cls_adv[cls_i]);
                let is_cls_i_grp1 = self.chip.gate().mul(ctx, is_cls_i, is_less_mask);
                let is_cls_i_grp2 = self.chip.gate().mul(ctx, is_cls_i, is_geater_mask);
                proportion_cls_grp1[cls_i] = self.chip.gate().add(ctx, proportion_cls_grp1[cls_i], is_cls_i_grp1);
                proportion_cls_grp2[cls_i] = self.chip.gate().add(ctx, proportion_cls_grp2[cls_i], is_cls_i_grp2);
            }
        }
        let num_samples = BigUint::from(cnt as u64);
        let num_bits = (2 * PRECISION_BITS + 1) as usize;
        let scale = QuantumCell::Constant(self.chip.quantization_scale);
        num_group1 = self.chip.gate().mul(ctx, num_group1, scale);
        num_group2 = self.chip.gate().mul(ctx, num_group2, scale);
        let mut gini_grp1 = ctx.load_constant(self.chip.quantization_scale);
        for pi in proportion_cls_grp1 {
            let pi_q = self.chip.gate().mul(ctx, pi, scale);
            let (pi_cls, _) = self.chip.range_gate().div_mod_var(ctx, pi_q, num_group1, num_bits * 2, num_bits);
            let pi_cls_square = self.square(ctx, pi_cls);
            gini_grp1 = self.chip.gate().sub(ctx, gini_grp1, pi_cls_square);
        }
        let (weight_grp1, _) = self.chip.range_gate().div_mod(ctx, num_group1, num_samples.clone(), num_bits);
        gini_grp1 = self.chip.gate().mul(ctx, gini_grp1, weight_grp1);
        gini_grp1 = self.chip.range_gate().div_mod_var(ctx, gini_grp1, weight_grp1, num_bits * 2, num_bits).0;
        let mut gini_grp2 = ctx.load_constant(self.chip.quantization_scale);
        for pi in proportion_cls_grp2 {
            let pi_q = self.chip.gate().mul(ctx, pi, scale);
            let (pi_cls, _) = self.chip.range_gate().div_mod_var(ctx, pi_q, num_group2, num_bits * 2, num_bits);
            let pi_cls_square = self.square(ctx, pi_cls);
            gini_grp2 = self.chip.gate().sub(ctx, gini_grp2, pi_cls_square);
        }
        let (weight_grp2, _) = self.chip.range_gate().div_mod(ctx, num_group2, num_samples, num_bits);
        gini_grp2 = self.chip.gate().mul(ctx, gini_grp2, weight_grp2);
        gini_grp2 = self.chip.range_gate().div_mod_var(ctx, gini_grp2, weight_grp2, num_bits * 2, num_bits).0;
        let gini = self.chip.gate().add(ctx, gini_grp1, gini_grp2);

        gini
    }
}