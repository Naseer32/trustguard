"""
FAKE, MINIMAL stand-in for the `genlayer` SDK.

PURPOSE: let the pure logic of contracts/trustguard.py run in plain Python when
the real GenLayer toolchain cannot be installed. It is NOT the GenLayer runtime:
  * no consensus, no validators, no real LLM, no GenVM sandbox
  * no storage-type restrictions (real storage forbids int/list/dict etc.)
  * no transactional rollback on revert (the contract validates before mutating)
Passing tests against this fake say nothing about on-chain behaviour.
"""
import types

__all__ = ["gl", "TreeMap", "DynArray", "u256", "Address", "allow_storage"]


class u256(int):
    pass


class TreeMap(dict):
    def __class_getitem__(cls, item):
        return cls


class DynArray(list):
    def __class_getitem__(cls, item):
        return cls


class Address:
    def __init__(self, hex_str: str):
        self.as_hex = hex_str.lower()

    def __eq__(self, other):
        return isinstance(other, Address) and self.as_hex == other.as_hex

    def __hash__(self):
        return hash(self.as_hex)


def allow_storage(cls):
    return cls


class _UserError(Exception):
    def __init__(self, message=""):
        super().__init__(message)
        self.message = message


class _Return:
    def __init__(self, calldata):
        self.calldata = calldata


def _run_nondet_unsafe(leader_fn, validator_fn):
    try:
        value = leader_fn()
    except Exception as exc:  # real runtime: leader error -> validators reject -> rotation
        raise _UserError(f"leader failed: {exc}")
    if not validator_fn(_Return(value)):
        raise _UserError("validators disagreed with leader")
    return value


class _Contract:
    def __new__(cls, *args, **kwargs):
        obj = super().__new__(cls)
        for name, annotation in getattr(cls, "__annotations__", {}).items():
            origin = annotation if isinstance(annotation, type) else None
            if origin is TreeMap:
                setattr(obj, name, TreeMap())
            elif origin is DynArray:
                setattr(obj, name, DynArray())
        return obj


def _view(fn):
    return fn


def _write(fn):
    return fn


class _Public:
    view = staticmethod(_view)
    write = staticmethod(_write)


gl = types.SimpleNamespace(
    Contract=_Contract,
    public=_Public,
    message=types.SimpleNamespace(sender_address=Address("0x" + "11" * 20)),
    message_raw={"datetime": "2026-10-13T08:00:00Z"},
    nondet=types.SimpleNamespace(exec_prompt=lambda prompt, response_format=None: "{}"),
    vm=types.SimpleNamespace(
        Return=_Return, UserError=_UserError, run_nondet_unsafe=_run_nondet_unsafe
    ),
)
