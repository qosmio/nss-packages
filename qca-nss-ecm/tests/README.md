# Directional UDP QoS regression

Run `python3 test_directional_qos.py --source /path/to/prepared/qca-nss-ecm`.
The source should include this feed's patch series. Requires Python 3 and a
C11 compiler, with no router, root access or packet generator.

The test compiles actual DSCP classifier helpers and protocol statements,
plus the four NSS CREATE QoS/IGS assignment blocks, using mocked CT/skb and
kernel surroundings. IGS disabled/enabled variants compile with warnings as
errors. It covers zero priorities, sender/CT direction reversal, acceleration
delay, partial flags, bidirectional cache, TCP and CREATE propagation.

On ECM `30fbfa493d700270ac6c14685290f340b6ead28c` plus the preceding 19 feed
patches, the unmodified classifier fails 196 checks in each variant. Patch
0026 gives 1,838/3,182 checks with zero failures. The same result holds on
QSDK 14.0 `7894b769eeb64f1c44fde547a107a8b866997590` plus the JuliusBairaktaris
feed's 20 patches at `c3bc04aa2f7bba688309b7b0356b558fe1fdad34`.

These are source statement regressions, not a full module build, firmware
CREATE acknowledgement or wireless queue observation. The default single
packet fallback remains intact unless both conntrack PRIO flags are set.
