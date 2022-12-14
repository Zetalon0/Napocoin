// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    int nHeight = pindexLast->nHeight + 1; 
    // 1th Hard fork, reset difficulty
    if (nHeight == params.nForkOne)
        return UintToArith256(params.powNeoScryptLimit).GetCompact();
    int nTargetTimespan = params.nPowTargetTimespan;
    int nTargetSpacing = params.nPowTargetSpacing;

    int64_t nInterval = nTargetTimespan / nTargetSpacing;

    bool fHardFork = nHeight == params.nForkOne;
    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % nInterval != 0 && !fHardFork && nHeight < params.nForkOne)
    {
        return pindexLast->nBits;
    }

    if (params.fPowAllowMinDifficultyBlocks)
    {
        // Special difficulty rule for testnet:
        // If the new block's timestamp is more than 10 minutes
        // then allow mining of a min-difficulty block.
        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 10)
            return nProofOfWorkLimit;
    }

    // The 1st retarget after genesis
    if (nInterval >= nHeight)
        nInterval = nHeight - 1;

    // Go back by nInterval
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < nInterval; i++)
        pindexFirst = pindexFirst->pprev;

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), nTargetTimespan, nTargetSpacing, params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, int nTargetTimespan, int nTargetSpacing, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    int nHeight = pindexLast->nHeight + 1;
    int64_t nInterval = nTargetTimespan / nTargetSpacing;
    int nActualTimespanAvg = 0;

    if (nHeight >= params.nForkOne) {
        nInterval = 1;

        int pindexFirstShortTime = 0;
        int pindexFirstMediumTime = 0;
        const CBlockIndex* pindexFirstLong = pindexLast;
        for(int i = 0; pindexFirstLong && i < nInterval && i < nHeight - 1; i++) {
            pindexFirstLong = pindexFirstLong->pprev;
            if (i == 14)
                pindexFirstShortTime = pindexFirstLong->GetBlockTime();
            if (i == 119)
                pindexFirstMediumTime = pindexFirstLong->GetBlockTime();
        }
        int nActualTimespanShort = (pindexLast->GetBlockTime() - pindexFirstShortTime) / 15;
        int nActualTimespanMedium = (pindexLast->GetBlockTime() - pindexFirstMediumTime)/120;
        int nActualTimespanLong = (pindexLast->GetBlockTime() - pindexFirstLong->GetBlockTime())/480;

        nActualTimespanAvg = (nActualTimespanShort + nActualTimespanMedium + nActualTimespanLong) / 3;
    }

    if (nHeight >= params.nForkOne) {
        // Apply .25 damping
        nActualTimespan = nActualTimespanAvg + 3 * nTargetTimespan;
        nActualTimespan /= 4;
    }

    // The initial settings (0.25 difficulty limiter)
    int nActualTimespanMax = nTargetTimespan*5/4;
    int nActualTimespanMin = nTargetTimespan*4/5;

    // Limit adjustment step
    if(nActualTimespan < nActualTimespanMin)
        nActualTimespan = nActualTimespanMin;
    if(nActualTimespan > nActualTimespanMax)
        nActualTimespan = nActualTimespanMax;

    // Retarget
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;
    if (fShift)
        bnNew <<= 1;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
