import {
  AlertTriangle,
  Ban,
  Calculator,
  Clock,
  Dice5,
  Lock,
  RefreshCw,
} from "lucide-react";

import type { VulnerabilityKey } from "@/lib/types";

export const VULN_CLASSES = {
  reentrancy: {
    label: "Reentrancy",
    swc_id: "SWC-107",
    color: "red",
    description: "External call before state update enables recursive exploitation",
    icon: "RefreshCw",
  },
  access_control: {
    label: "Access Control",
    swc_id: "SWC-105",
    color: "orange",
    description: "Missing or incorrect authorization on sensitive functions",
    icon: "Lock",
  },
  arithmetic: {
    label: "Arithmetic Over/Underflow",
    swc_id: "SWC-101",
    color: "yellow",
    description: "Integer overflow/underflow in arithmetic operations",
    icon: "Calculator",
  },
  bad_randomness: {
    label: "Bad Randomness",
    swc_id: "SWC-120",
    color: "purple",
    description: "Predictable randomness from blockhash/timestamp",
    icon: "Dice5",
  },
  denial_of_service: {
    label: "Denial of Service",
    swc_id: "SWC-128",
    color: "pink",
    description: "Loops or external calls causing gas exhaustion",
    icon: "Ban",
  },
  time_manipulation: {
    label: "Time Manipulation",
    swc_id: "SWC-116",
    color: "blue",
    description: "Logic depending on block.timestamp manipulable by miners",
    icon: "Clock",
  },
  unchecked_low_level_calls: {
    label: "Unchecked Low-Level Calls",
    swc_id: "SWC-104",
    color: "indigo",
    description: "Return value of send/call/delegatecall not checked",
    icon: "AlertTriangle",
  },
} as const;

export const VULN_CLASS_LIST = Object.entries(VULN_CLASSES).map(([key, value]) => ({
  key: key as VulnerabilityKey,
  ...value,
}));

export const ICON_MAP = {
  RefreshCw,
  Lock,
  Calculator,
  Dice5,
  Ban,
  Clock,
  AlertTriangle,
};

export const SCAN_PROGRESS_PHASES = [
  {
    id: "parse",
    title: "Parsing Solidity source",
    description: "Memecah contract, function, dan control-flow dasar sebelum feature extraction.",
    duration: "Cepat",
  },
  {
    id: "features",
    title: "Extracting ML and rule features",
    description: "Menghitung heuristik, rule signals, dan representasi yang dipakai classifier.",
    duration: "Sedang",
  },
  {
    id: "classifiers",
    title: "Running XGBoost classifiers",
    description: "Menilai 7 kelas vulnerability dan menyusun status clean, suspected, atau detected.",
    duration: "Sedang",
  },
  {
    id: "rag",
    title: "Generating RAG explanation",
    description: "Mengambil knowledge-base lalu memanggil MiniMax untuk penjelasan dan mitigasi.",
    duration: "Paling lama",
  },
] as const;

export const DEFAULT_SOLIDITY_SNIPPET = `pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
}`;
