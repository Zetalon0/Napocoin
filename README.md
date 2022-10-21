What is Napocoin?
----------------

Napocoin is the cryptocurrency built for fast transactions
 - NeoScrypt Algorithm
 - Current Gen ASIC resistance
 - eHRC (enhanced Hash Rate Compensation)
 - ACP (Advanced Checkpointing)
 - SegWit (Segregated Witness) *
 - CLTV (CheckLockTimeVerify) *
 - CSV (Check Sequence Verify) *
 - 5 seconds block targets
 - block difficulty change every 10000 blocks
 - 1400 coins per block
 - deterministic inflation 
    - 1 coins/block after 10th halvings
    - 10 coins/block after 25th halvings
 - burn transation fee
 - subsidy halves in 3.5 million  blocks (~6 months)
 - retarget difficulty every block with 25% damping
 - 256 MB max block size
 - Default Napocoin network port is 8712
 - Default RPC mining port is 8711
 - 51200 TPS

For more information, as well as an immediately useable, binary version of
the Napocoin client sofware, see https://napocoin.net/.

License
-------

Napocoin is released under the terms of the MIT license. See `COPYING` for more
information or see http://opensource.org/licenses/MIT.

Development process
-------------------

Developers work in their own trees, then submit pull requests when they think
their feature or bug fix is ready.

If it is a simple/trivial/non-controversial change, then one of the Napocoin
development team members simply pulls it.

If it is a *more complicated or potentially controversial* change, then the patch
submitter will be asked to start a discussion with the devs and community.

The patch will be accepted if there is broad consensus that it is a good thing.
Developers should expect to rework and resubmit patches if the code doesn't
match the project's coding conventions (see `doc/coding.txt`) or are
controversial.

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/Zetalon0/Napocoin/tags) are created
regularly to indicate new official, stable release versions of Napocoin.
