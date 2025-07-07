package tfhe

var (
	ParamsEBS5 = ParametersLiteral[uint64]{
		LWEDimension:    1160,
		GLWERank:        1,
		PolyDegree:      2048,
		LookUpTableSize: 2048 * 2,

		LWEStdDev:  0.000000003704451841947947,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BlockSize: 1,

		MessageModulus: 1 << 5,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}
	ParamsEBS6 = ParametersLiteral[uint64]{
		LWEDimension:    1160,
		GLWERank:        1,
		PolyDegree:      2048,
		LookUpTableSize: 2048 * 4,

		LWEStdDev:  0.000000003704451841947947,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BlockSize: 1,

		MessageModulus: 1 << 6,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	ParamsEBS7 = ParametersLiteral[uint64]{
		LWEDimension:    1160,
		GLWERank:        1,
		PolyDegree:      2048,
		LookUpTableSize: 2048 * 8,

		LWEStdDev:  0.000000003704451841947947,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BlockSize: 1,

		MessageModulus: 1 << 7,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 2,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	ParamsEBS8 = ParametersLiteral[uint64]{
		LWEDimension:    1160,
		GLWERank:        1,
		PolyDegree:      2048,
		LookUpTableSize: 2048 * 16,

		LWEStdDev:  0.000000003704451841947947,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BlockSize: 1,

		MessageModulus: 1 << 8,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 2,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 3,
		},

		BootstrapOrder: OrderKeySwitchBlindRotate,
	}

	Params5 = ParametersLiteral[uint64]{
		LWEDimension:    1160,
		GLWERank:        1,
		PolyDegree:      2048 * 2,
		LookUpTableSize: 2048 * 2,

		LWEStdDev:  0.000000003704451841947947,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BlockSize: 1,

		MessageModulus: 1 << 5,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 1,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 3,
		},

		BootstrapOrder: OrderBlindRotateKeySwitch,
	}
	Params6 = ParametersLiteral[uint64]{
		LWEDimension:    1160,
		GLWERank:        1,
		PolyDegree:      2048 * 4,
		LookUpTableSize: 2048 * 4,

		LWEStdDev:  0.000000003704451841947947,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BlockSize: 1,

		MessageModulus: 1 << 6,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 2,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 3,
		},

		BootstrapOrder: OrderBlindRotateKeySwitch,
	}

	Params7 = ParametersLiteral[uint64]{
		LWEDimension:    1160,
		GLWERank:        1,
		PolyDegree:      2048 * 8,
		LookUpTableSize: 2048 * 8,

		LWEStdDev:  0.000000003704451841947947,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BlockSize: 1,

		MessageModulus: 1 << 7,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 2,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 3,
		},

		BootstrapOrder: OrderBlindRotateKeySwitch,
	}

	Params8 = ParametersLiteral[uint64]{
		LWEDimension:    1160,
		GLWERank:        1,
		PolyDegree:      2048 * 16,
		LookUpTableSize: 2048 * 16,

		LWEStdDev:  0.000000003704451841947947,
		GLWEStdDev: 0.0000000000000003472576015484159,

		BlockSize: 1,

		MessageModulus: 1 << 8,

		BlindRotateParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 22,
			Level: 2,
		},
		KeySwitchParameters: GadgetParametersLiteral[uint64]{
			Base:  1 << 7,
			Level: 3,
		},

		BootstrapOrder: OrderBlindRotateKeySwitch,
	}
)
