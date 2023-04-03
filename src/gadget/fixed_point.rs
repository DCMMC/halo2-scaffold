use halo2_base::{
    utils::{ScalarField, BigPrimeField}, gates::{GateChip, GateInstructions, RangeChip, range::RangeStrategy, RangeInstructions},
    QuantumCell, Context, AssignedValue
};
use halo2_base::QuantumCell::{Constant, Existing, Witness};
use num_bigint::BigUint;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FixedPointStrategy {
    Vertical, // vanilla implementation with vertical basic gate(s)
}

// #[derive(Clone, Debug)]
// pub struct FixedPointConfig<F: ScalarField> {
//     pub gate: FlexGateConfig<F>,
//     _strategy: FixedPointStrategy,
// }

// impl<F: ScalarField> FixedPointConfig<F> {
//     pub fn configure(
//         meta: &mut ConstraintSystem<F>,
//         range_strategy: FixedPointStrategy,
//         num_advice: &[usize],
//         num_fixed: usize,
//         circuit_degree: usize,
//     ) -> Self {
//         let gate = FlexGateConfig::configure(
//             meta,
//             match range_strategy {
//                 FixedPointStrategy::Vertical => GateStrategy::Vertical,
//             },
//             num_advice,
//             num_fixed,
//             circuit_degree,
//         );
//         let mut config =
//             Self { gate, _strategy: range_strategy };

//         config.gate.max_rows = 1 << circuit_degree;

//         config
//     }
// }

#[derive(Clone, Debug)]
pub struct FixedPointChip<F: ScalarField> {
    strategy: FixedPointStrategy,
    pub gate: RangeChip<F>,
    pub precision_bits: usize
}

impl<F: ScalarField> FixedPointChip<F> {
    pub fn new(strategy: FixedPointStrategy, lookup_bits: usize) -> Self {
        let gate = RangeChip::new(
            match strategy {
                FixedPointStrategy::Vertical => RangeStrategy::Vertical,
            },
            lookup_bits
        );
        // 128 = 96 + 32
        let precision_bits = 128;

        Self { strategy, gate, precision_bits }
    }

    pub fn default(lookup_bits: usize) -> Self {
        Self::new(FixedPointStrategy::Vertical, lookup_bits)
    }
}

pub trait FixedPointInstructions<F: ScalarField> {
    /// Fixed point decimal and its arithmetic functions.
    /// [ref] https://github.com/XMunkki/FixPointCS/blob/c701f57c3cfe6478d1f6fd7578ae040c59386b3d/Cpp/Fixed64.h
    /// [ref] https://github.com/abdk-consulting/abdk-libraries-solidity/blob/master/ABDKMath64x64.sol
    ///
    /// TODO (Wentao XIAO) add more configurable precision, e.g., 64.64
    /// TODO (Wentao XIAO) now FixedPointChip only works on positve numbers, should support negative numbers in the future
    type Gate: GateInstructions<F>;
    type RangeGate: RangeInstructions<F>;

    fn gate(&self) -> &Self::Gate;
    fn range_gate(&self) -> &Self::RangeGate;
    fn strategy(&self) -> FixedPointStrategy;

    /// Return qmul30 of a and b for 32.32 fixed point deciamls
    fn qmul30(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>
    ) -> AssignedValue<F>
    where
        F: BigPrimeField;
    
    /// Return the approximation of exp2 with poly4 which is something like Taylor expansion. Precision: 18.19 bits
    fn exp2poly4(&self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>) -> AssignedValue<F>
    where
        F: BigPrimeField;

    /// Return mul of a and b for 32.32 fixed point decimals
    fn mul(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>
    ) -> AssignedValue<F>
    where
        F: BigPrimeField;

    /// exp2fast
    fn exp2fast(&self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>) -> AssignedValue<F>
    where
        F: BigPrimeField;

    /// exp
    fn exp(&self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>) -> AssignedValue<F>
    where
        F: BigPrimeField;

    /// div mod and rem, e.g., 103 / 100 = 1 ... 3 will return 1 and 3
    fn div_mod(
        &self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>, b: impl Into<BigUint>
    ) -> (AssignedValue<F>, AssignedValue<F>)
    where
        F: BigPrimeField;
    
    fn check_power_of_two(&self, ctx: &mut Context<F>, pow2_exponent: AssignedValue<F>, exponent: AssignedValue<F>)
    where
        F: BigPrimeField;
}

impl<F: ScalarField> FixedPointInstructions<F> for FixedPointChip<F> {
    type Gate = GateChip<F>;
    type RangeGate = RangeChip<F>;

    fn range_gate(&self) -> &Self::RangeGate {
        &self.gate
    }

    fn gate(&self) -> &Self::Gate {
        &self.gate.gate()
    }

    fn strategy(&self) -> FixedPointStrategy {
        self.strategy
    }

    fn qmul30(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>
    ) -> AssignedValue<F>
    where
        F: BigPrimeField,
    {
        let ab = self.gate().mul(ctx, a, b);
        self.range_gate().range_check(ctx, ab, self.precision_bits);
        let (ab30, _) = self.div_mod(ctx, Existing(ab), 1u128 << 30);

        ab30
    }

    fn exp2poly4(&self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>) -> AssignedValue<F>
    where
        F: BigPrimeField,
    {
        let a = a.into();
        let y0 = self.qmul30(ctx, a, Constant(F::from(14555373)));
        let y01 = self.gate().add(ctx, Existing(y0), Constant(F::from(55869331)));
        let y1 = self.qmul30(ctx, a, Existing(y01));
        let y11 = self.gate().add(ctx, Existing(y1), Constant(F::from(259179547)));
        let y2 = self.qmul30(ctx, a, Existing(y11));
        let y21 = self.gate().add(ctx, Existing(y2), Constant(F::from(744137573)));
        let y3 = self.qmul30(ctx, a, Existing(y21));
        let y4 = self.gate().add(ctx, Existing(y3), Constant(F::from(1073741824)));
        
        y4
    }

    fn mul(
        &self,
        ctx: &mut Context<F>,
        a: impl Into<QuantumCell<F>>,
        b: impl Into<QuantumCell<F>>
    ) -> AssignedValue<F>
    where
        F: BigPrimeField,
    {
        let y0 = self.gate().mul(ctx, a, b);
        self.range_gate().range_check(ctx, y0, self.precision_bits);
        let (y1, _) = self.div_mod(ctx, Existing(y0), 0x100000000u128);

        y1
    }

    fn div_mod(
        &self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>, b: impl Into<BigUint>
    ) -> (AssignedValue<F>, AssignedValue<F>)
    where
        F: BigPrimeField,
    {
        let a_num_bits = self.precision_bits;
        let (div, rem) = self.range_gate().div_mod(ctx, a, b, a_num_bits);

        (div, rem)
    }

    fn check_power_of_two(&self, ctx: &mut Context<F>, pow2_exponent: AssignedValue<F>, exponent: AssignedValue<F>)
    where
        F: BigPrimeField,
    {
        let range_bits = self.precision_bits;
        let bits = self.gate().num_to_bits(ctx, pow2_exponent, range_bits);
        let sum_of_bits = self.gate().sum(ctx, bits.clone());
        let sum_of_bits_m1 = self.gate().sub(ctx, sum_of_bits, Constant(F::one()));
        let is_zero = self.gate().is_zero(ctx, sum_of_bits_m1);
        // ensure the bits of pow2_exponent has only one of bit one.
        self.gate().assert_is_const(ctx, &is_zero, &F::one());
        let bit = self.gate().select_from_idx(
            ctx, 
            bits.into_iter().map(|x| Existing(x)), 
            exponent
        );
        let bit_m1 = self.gate().sub(ctx, bit, Constant(F::one()));
        let is_zero_bit_m1 = self.gate().is_zero(ctx, bit_m1);
        // ensures bits[expnent] is exact bit one
        self.gate().assert_is_const(ctx, &is_zero_bit_m1, &F::one());
    }

    fn exp2fast(&self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>) -> AssignedValue<F>
    where
        F: BigPrimeField,
    {
        let a = a.into();
        let (_, k_rem) = self.div_mod(ctx, a, 0x100000000u128);
        let (k, _) = self.div_mod(ctx, Existing(k_rem), 4u128);
        let y0 = self.exp2poly4(ctx, Existing(k));
        self.range_gate().range_check(ctx, y0, self.precision_bits);
        let y1 = self.gate().mul(ctx, Existing(y0), Constant(F::from(4)));
        let (int_part, _) = self.div_mod(ctx, a, 0x100000000u128);
        let int_part_pow2 = self.gate().pow_of_two()[int_part.value().get_lower_32() as usize];
        // NOTE (Wentao XIAO) to make use of int_part_pow2 as a Witness, we must first check it's a correct pow2 of int_part.
        let int_part_pow2_witness = self.gate().add(ctx, Witness(int_part_pow2), Constant(F::zero()));
        self.check_power_of_two(ctx, int_part_pow2_witness, int_part);
        let res = self.gate().mul(ctx, Existing(y1), int_part_pow2_witness);
        self.range_gate().range_check(ctx, res, self.precision_bits);

        res
    }

    fn exp(&self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>) -> AssignedValue<F>
    where
        F: BigPrimeField
    {
        let a = a.into();
        let rcp_ln2 = Constant(F::from(0x171547652));
        let y0 = self.mul(ctx, a, rcp_ln2);
        self.range_gate().range_check(ctx, y0, self.precision_bits);
        let y1 = self.exp2fast(ctx, Existing(y0));
        self.range_gate().range_check(ctx, y1, self.precision_bits);

        y1
    }
}
