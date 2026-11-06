"""The investigation agent. Written after the hackathon kickoff.

Trust boundary: the model only proposes. `policy` decides what runs, the sandbox and
firewall enforce it, and `verify` reports what the evidence shows. No security control
depends on the model behaving.
"""
