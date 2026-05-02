export const DEMO_CONTRACTS = [
  {
    slug: "the-dao",
    label: "The DAO",
    focus: "reentrancy",
    description: "Classic recursive withdrawal pattern that inspired SWC-107 examples.",
    filename: "reentrancy_dao.sol",
  },
  {
    slug: "parity-wallet",
    label: "Parity Wallet",
    focus: "access_control",
    description: "A historical ownership initialization issue tied to privileged wallet logic.",
    filename: "parity_wallet_bug_2.sol",
  },
  {
    slug: "bec-token",
    label: "BEC Token",
    focus: "arithmetic",
    description: "Integer arithmetic flaws that enabled balance inflation in the wild.",
    filename: "BECToken.sol",
  },
] as const;
