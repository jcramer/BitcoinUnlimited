// Copyright (c) 2015-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "tokengroups.h"
#include "base58.h"
#include "cashaddrenc.h"
#include "coincontrol.h"
#include "coins.h"
#include "consensus/validation.h"
#include "dstencode.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "random.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/standard.h"
#include "unlimited.h"
#include "utilmoneystr.h"
#include "wallet/wallet.h"
#include <algorithm>

extern CChain chainActive;
extern CCriticalSection cs_main;
bool EnsureWalletIsAvailable(bool avoidException);

static const CAmount GROUPED_SATOSHI_AMT = 1;

/* Grouped transactions look like this:

GP2PKH:

OP_DATA(group identifier)
OP_DATA(SerializeAmount(amount))
OP_GROUP
OP_DROP
OP_DUP
OP_HASH160
OP_DATA(pubkeyhash)
OP_EQUALVERIFY
OP_CHECKSIG

GP2SH:

OP_DATA(group identifier)
OP_DATA(CompactSize(amount))
OP_GROUP
OP_DROP
OP_HASH160 [20-byte-hash-value] OP_EQUAL

FUTURE: GP2SH version 2:

OP_DATA(group identifier)
OP_DATA(CompactSize(amount))
OP_GROUP
OP_DROP
OP_HASH256 [32-byte-hash-value] OP_EQUAL
*/

CTokenGroupID NoGroup; // No group specified.

// Approximate size of signature in a script -- used for guessing fees
const unsigned int TX_SIG_SCRIPT_LEN = 72;

bool IsAnyTxOutputGrouped(const CTransaction &tx)
{
    for (const CTxOut &txout : tx.vout)
    {
        CTokenGroupPair grp = GetTokenGroupPair(txout.scriptPubKey);
        if (grp.invalid)
            return true; // Its still grouped even if invalid
        if (grp.associatedGroup != NoGroup)
            return true;
    }

    return false;
}

CTokenGroupID GetTokenGroup(const CScript &script) { return GetTokenGroupPair(script).associatedGroup; }
std::vector<unsigned char> SerializeAmount(CAmount num)
{
    if (num < 0)
        throw std::ios_base::failure("SerializeAmount(): negative number");
    CDataStream strm(SER_NETWORK, CLIENT_VERSION);
    if (num < 256)
    {
        ser_writedata8(strm, num);
    }
    else if (num <= std::numeric_limits<unsigned short>::max())
    {
        ser_writedata16(strm, num);
    }
    else if (num <= std::numeric_limits<unsigned int>::max())
    {
        ser_writedata32(strm, num);
    }
    else
    {
        ser_writedata64(strm, num);
    }
    return std::vector<unsigned char>(strm.begin(), strm.end());
}

CAmount DeserializeAmount(std::vector<unsigned char> &vec)
{
    int sz = vec.size();
    if (sz == 1)
    {
        return vec[0];
    }
    CDataStream strm(vec, SER_NETWORK, CLIENT_VERSION);
    if (sz == 2)
    {
        return ser_readdata16(strm);
    }
    if (sz == 4)
    {
        return ser_readdata32(strm);
    }
    if (sz == 8)
    {
        uint64_t v = ser_readdata64(strm);
        if (v > std::numeric_limits<CAmount>::max())
            throw std::ios_base::failure("DeserializeAmount(): overflow");
        return v;
    }
    throw std::ios_base::failure("DeserializeAmount(): invalid format");
}


CTokenGroupPair GetTokenGroupPair(const CScript &script)
{
    CTokenGroupPair ret;
    CScript::const_iterator pc = script.begin();
    std::vector<unsigned char> groupId;
    std::vector<unsigned char> tokenQty;
    std::vector<unsigned char> data;
    opcodetype opcode;
    opcodetype opcodeGrp;
    opcodetype opcodeQty;

    // The destination address could also be the group so I need to get it
    CTxDestination address;
    txnouttype whichType;

    ret.invalid = false; // these early returns are not invalid -- they are just not OP_GROUP

    if (!ExtractDestinationAndType(script, address, whichType))
    {
        ret.mintMeltGroup = NoGroup;
    }
    else
    {
        // only certain well known script types are allowed to mint or melt
        if ((whichType == TX_PUBKEYHASH) || (whichType == TX_SCRIPTHASH) || (whichType == TX_GRP_PUBKEYHASH) ||
            (whichType == TX_GRP_SCRIPTHASH))
            ret.mintMeltGroup = address;
    }

    if (!script.GetOp(pc, opcodeGrp, groupId))
    {
        ret.associatedGroup = NoGroup;
        return ret;
    }

    if (!script.GetOp(pc, opcodeQty, tokenQty))
    {
        DbgAssert(!"empty script", ); // this should be impossible since that means script with 1 byte
        ret.associatedGroup = NoGroup;
        return ret;
    }

    if (!script.GetOp(pc, opcode, data))
    {
        DbgAssert(!"empty script", ); // this should be impossible since that means script with 1 byte
        ret.associatedGroup = NoGroup;
        return ret;
    }

    if (opcode != OP_GROUP)
    {
        ret.associatedGroup = NoGroup;
        return ret;
    }
    else // If OP_GROUP is used, enforce rules on the other fields
    {
        // group must be 20 or 32 bytes
        if ((opcodeGrp != 0x14) && (opcodeGrp != 0x20))
        {
            ret.invalid = true;
            return ret;
        }
        // quantity must be 1, 2, 4, or 8 bytes
        if ((opcodeQty != 1) && (opcodeQty != 2) && (opcodeQty != 4) && (opcodeQty != 8))
        {
            ret.invalid = true;
            return ret;
        }
    }

    try
    {
        ret.quantity = DeserializeAmount(tokenQty);
    }
    catch (std::ios_base::failure &f)
    {
        ret.invalid = true;
    }
    ret.associatedGroup = groupId;
    return ret;
}


// local class that just keeps track of the amounts of each group coming into and going out of a transaction
class CBalance
{
public:
    CBalance() : mintMelt(false), input(0), output(0) {}
    CTokenGroupPair groups; // possible groups
    bool mintMelt;
    CAmount input;
    CAmount output;
};

bool CheckTokenGroups(const CTransaction &tx, CValidationState &state, const CCoinsViewCache &view)
{
    std::unordered_map<CTokenGroupID, CBalance> gBalance;

    // Iterate through all the outputs constructing the final balances of every group.
    for (const auto &outp : tx.vout)
    {
        const CScript &scriptPubKey = outp.scriptPubKey;
        CTokenGroupPair tokenGrp = GetTokenGroupPair(scriptPubKey);
        if (tokenGrp.invalid)
            return state.Invalid(false, REJECT_INVALID, "bad OP_GROUP");
        if (tokenGrp.associatedGroup != NoGroup)
            gBalance[tokenGrp.associatedGroup].output += tokenGrp.quantity;
    }

    // Now iterate through the inputs applying them to match outputs.
    // If any input utxo address matches a non-bitcoin group address, defer since this could be a mint or burn
    for (const auto &inp : tx.vin)
    {
        const COutPoint &prevout = inp.prevout;
        const Coin &coin = view.AccessCoin(prevout);
        if (coin.IsSpent()) // should never happen because you've already CheckInputs(tx,...)
        {
            DbgAssert(!"Checking token group for spent coin", );
            return state.Invalid(false, REJECT_INVALID, "already-spent");
        }
        // no prior coins can be grouped.
        if (coin.nHeight < miningEnforceOpGroup.value)
            continue;
        const CScript &script = coin.out.scriptPubKey;
        CTokenGroupPair tokenGrp = GetTokenGroupPair(script);
        // The prevout should never be invalid because that would mean that this node accepted a block with an
        // invalid OP_GROUP tx in it.
        if (tokenGrp.invalid)
            continue;
        CAmount amount = tokenGrp.quantity;
        if (tokenGrp.mintMeltGroup != NoGroup)
        {
            gBalance[tokenGrp.mintMeltGroup].mintMelt = true;
        }
        if (tokenGrp.associatedGroup != NoGroup)
        {
            gBalance[tokenGrp.associatedGroup].input += amount;
        }

        // Implement a limited quantity token via a one-time mint operation
        // by minting to the sha256 of a COutPoint.  A COutPoint provides entropy (is extremely likely to be unique)
        // because it contains the sha256 of the input tx and an index.
        CHashWriter oneTimeGrp(SER_GETHASH, PROTOCOL_VERSION);
        oneTimeGrp << prevout;
        CTokenGroupID otg(oneTimeGrp.GetHash());

        auto item = gBalance.find(otg); // Is there an output to this group?
        if (item != gBalance.end()) // If so, indicate that it can be minted
        {
            item->second.mintMelt = true;
        }
    }

    // Now pass thru the outputs ensuring balance or mint/melt permission
    for (auto &txo : gBalance)
    {
        CBalance &bal = txo.second;
        if (!bal.mintMelt && (bal.input != bal.output))
        {
            return state.Invalid(false, REJECT_GROUP_IMBALANCE, "grp-invalid-mint",
                "Group output exceeds input, including all mintable");
        }
    }

    return true;
}

class CTxDestinationTokenGroupExtractor : public boost::static_visitor<CTokenGroupID>
{
public:
    CTokenGroupID operator()(const CKeyID &id) const { return CTokenGroupID(id); }
    CTokenGroupID operator()(const CScriptID &id) const { return CTokenGroupID(id); }
    CTokenGroupID operator()(const CNoDestination &) const { return CTokenGroupID(); }
};

CTokenGroupID::CTokenGroupID(const CTxDestination &id)
{
    *this = boost::apply_visitor(CTxDestinationTokenGroupExtractor(), id);
}

bool CTokenGroupID::isUserGroup(void) const { return (!data.empty()); }
CTokenGroupID::CTokenGroupID(const std::string &addr, const CChainParams &params)
{
    CashAddrContent cac = DecodeCashAddrContent(addr, params);
    if (cac.type == CashAddrType::GROUP_TYPE)
        data = cac.hash;
    // otherwise it becomes NoGroup (i.e. data is size 0)
}

std::string CTokenGroupID::Encode(const CChainParams &params) const
{
    return EncodeCashAddr(data, CashAddrType::GROUP_TYPE, params);
}

CTxDestination CTokenGroupID::ControllingAddress() const
{
    // TODO figure out whether this is a script or p2pkh address
    return CTxDestination(CKeyID(uint160(data)));
}

class CGroupScriptVisitor : public boost::static_visitor<bool>
{
private:
    CScript *script;
    CTokenGroupID group;
    CAmount quantity;

public:
    CGroupScriptVisitor(CTokenGroupID grp, CAmount qty, CScript *scriptin) : group(grp), quantity(qty)
    {
        script = scriptin;
    }
    bool operator()(const CNoDestination &dest) const
    {
        script->clear();
        return false;
    }

    bool operator()(const CKeyID &keyID) const
    {
        script->clear();
        if (group.isUserGroup())
        {
            *script << group.bytes() << SerializeAmount(quantity) << OP_GROUP << OP_DROP << OP_DROP << OP_DUP
                    << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        }
        else
        {
            *script << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        }
        return true;
    }

    bool operator()(const CScriptID &scriptID) const
    {
        script->clear();
        if (group.isUserGroup())
        {
            *script << group.bytes() << SerializeAmount(quantity) << OP_GROUP << OP_DROP << OP_DROP << OP_HASH160
                    << ToByteVector(scriptID) << OP_EQUAL;
        }
        else
        {
            *script << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
        }
        return true;
    }
};

void GetAllGroupBalances(const CWallet *wallet, std::unordered_map<CTokenGroupID, CAmount> &balances)
{
    std::vector<COutput> coins;
    wallet->FilterCoins(coins, [&balances](const CWalletTx *tx, const CTxOut *out) {
        CTokenGroupPair tg = GetTokenGroupPair(out->scriptPubKey);
        if (tg.associatedGroup != NoGroup) // must be sitting in any group address
        {
            if (tg.quantity > std::numeric_limits<CAmount>::max() - balances[tg.associatedGroup])
                balances[tg.associatedGroup] = std::numeric_limits<CAmount>::max();
            else
                balances[tg.associatedGroup] += tg.quantity;
        }
        return false; // I don't want to actually filter anything
    });
}

CAmount GetGroupBalance(const CTokenGroupID &grpID, const CTxDestination &dest, const CWallet *wallet)
{
    std::vector<COutput> coins;
    CAmount balance = 0;
    wallet->FilterCoins(coins, [grpID, dest, &balance](const CWalletTx *tx, const CTxOut *out) {
        CTokenGroupPair tg = GetTokenGroupPair(out->scriptPubKey);
        if (grpID == tg.associatedGroup) // must be sitting in group address
        {
            if ((dest == CTxDestination(CNoDestination())) || (CTokenGroupID(dest) == tg.mintMeltGroup))
            {
                if (tg.quantity > std::numeric_limits<CAmount>::max() - balance)
                    balance = std::numeric_limits<CAmount>::max();
                else
                    balance += tg.quantity;
            }
        }
        return false;
    });
    return balance;
}

CScript GetScriptForDestination(const CTxDestination &dest, const CTokenGroupID &group, const CAmount &amount)
{
    CScript script;

    boost::apply_visitor(CGroupScriptVisitor(group, amount, &script), dest);
    return script;
}

static CAmount AmountFromIntegralValue(const UniValue &value)
{
    if (!value.isNum() && !value.isStr())
        throw std::runtime_error("Amount is not a number or string");
    int64_t val = atoi64(value.getValStr());
    CAmount amount = val;
    return amount;
}


// extracts a common RPC call parameter pattern.  Returns curparam.
static unsigned int ParseGroupAddrValue(const UniValue &params,
    unsigned int curparam,
    CTokenGroupID &grpID,
    std::vector<CRecipient> &outputs,
    CAmount &totalValue,
    bool groupedOutputs)
{
    grpID = CTokenGroupID(params[curparam].get_str());
    if (!grpID.isUserGroup())
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
    }
    outputs.reserve(params.size() / 2);
    curparam++;
    totalValue = 0;
    while (curparam + 1 < params.size())
    {
        CTxDestination dst = DecodeDestination(params[curparam].get_str(), Params());
        if (dst == CTxDestination(CNoDestination()))
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: destination address");
        }
        CAmount amount = AmountFromIntegralValue(params[curparam + 1]);
        if (amount <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid parameter: amount");
        CScript script;
        CRecipient recipient;
        if (groupedOutputs)
        {
            script = GetScriptForDestination(dst, grpID, amount);
            recipient = {script, GROUPED_SATOSHI_AMT, false};
        }
        else
        {
            script = GetScriptForDestination(dst, NoGroup, 0);
            recipient = {script, amount, false};
        }

        totalValue += amount;
        outputs.push_back(recipient);
        curparam += 2;
    }
    return curparam;
}

bool NearestGreaterCoin(const std::vector<COutput> &coins, CAmount amt, COutput &chosenCoin)
{
    bool ret = false;
    CAmount curBest = std::numeric_limits<CAmount>::max();

    for (const auto &coin : coins)
    {
        CAmount camt = coin.GetValue();
        if ((camt > amt) && (camt < curBest))
        {
            curBest = camt;
            chosenCoin = coin;
            ret = true;
        }
    }

    return ret;
}


CAmount CoinSelection(const std::vector<COutput> &coins, CAmount amt, std::vector<COutput> &chosenCoins)
{
    // simple algorithm grabs until amount exceeded
    CAmount cur = 0;

    for (const auto &coin : coins)
    {
        chosenCoins.push_back(coin);
        cur += coin.GetValue();
        if (cur >= amt)
            break;
    }
    return cur;
}

CAmount GroupCoinSelection(const std::vector<COutput> &coins, CAmount amt, std::vector<COutput> &chosenCoins)
{
    // simple algorithm grabs until amount exceeded
    CAmount cur = 0;

    for (const auto &coin : coins)
    {
        chosenCoins.push_back(coin);
        CTokenGroupPair tg = GetTokenGroupPair(coin.tx->vout[coin.i].scriptPubKey);
        cur += tg.quantity;
        if (cur >= amt)
            break;
    }
    return cur;
}


void ConstructTx(CWalletTx &wtxNew,
    const std::vector<COutput> &chosenCoins,
    const std::vector<CRecipient> &outputs,
    CAmount totalAvailable,
    CAmount totalNeeded,
    CTokenGroupID grpID,
    CWallet *wallet)
{
    std::string strError;
    CMutableTransaction tx;
    CReserveKey groupChangeKeyReservation(wallet);
    CReserveKey feeChangeKeyReservation(wallet);

    {
        if (GetRandInt(10) == 0)
            tx.nLockTime = std::max(0, (int)tx.nLockTime - GetRandInt(100));
        assert(tx.nLockTime <= (unsigned int)chainActive.Height());
        assert(tx.nLockTime < LOCKTIME_THRESHOLD);
        unsigned int approxSize = 0;

        // Add group input and output
        for (const CRecipient &recipient : outputs)
        {
            CTxOut txout(recipient.nAmount, recipient.scriptPubKey);
            tx.vout.push_back(txout);
            approxSize += ::GetSerializeSize(txout, SER_DISK, CLIENT_VERSION);
        }

        unsigned int inpSize = 0;
        for (const auto &coin : chosenCoins)
        {
            CTxIn txin(coin.GetOutPoint(), CScript(), std::numeric_limits<unsigned int>::max() - 1);
            tx.vin.push_back(txin);
            inpSize = ::GetSerializeSize(txin, SER_DISK, CLIENT_VERSION) + TX_SIG_SCRIPT_LEN;
            approxSize += inpSize;
        }

        if (totalAvailable > totalNeeded) // need to make a group change output
        {
            CPubKey newKey;

            if (!groupChangeKeyReservation.GetReservedKey(newKey))
                throw JSONRPCError(
                    RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

            CTxOut txout(
                GROUPED_SATOSHI_AMT, GetScriptForDestination(newKey.GetID(), grpID, totalAvailable - totalNeeded));
            tx.vout.push_back(txout);
            approxSize += ::GetSerializeSize(txout, SER_DISK, CLIENT_VERSION);
        }

        // Add another input for the bitcoin used for the fee
        // this ignores the additional change output
        approxSize += inpSize;

        // Now add bitcoin fee
        CAmount fee = wallet->GetRequiredFee(approxSize);

        // find a fee input
        std::vector<COutput> bchcoins;
        wallet->FilterCoins(bchcoins, [](const CWalletTx *tx, const CTxOut *out) {
            CTokenGroupPair tg = GetTokenGroupPair(out->scriptPubKey);
            return NoGroup == tg.associatedGroup;
        });

        COutput feeCoin(nullptr, 0, 0, false);
        if (!NearestGreaterCoin(bchcoins, fee, feeCoin))
        {
            strError = strprintf("Not enough funds for fee of %d.", FormatMoney(fee));
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
        }

        CTxIn txin(feeCoin.GetOutPoint(), CScript(), std::numeric_limits<unsigned int>::max() - 1);
        tx.vin.push_back(txin);

        if (feeCoin.GetValue() > 2 * fee) // make change if input is too big
        {
            CPubKey newKey;

            if (!feeChangeKeyReservation.GetReservedKey(newKey))
                throw JSONRPCError(
                    RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

            CTxOut txout(feeCoin.GetValue() - fee, GetScriptForDestination(newKey.GetID()));
            tx.vout.push_back(txout);
        }

        if (!wallet->SignTransaction(tx))
        {
            throw JSONRPCError(RPC_WALLET_ERROR, "Signing transaction failed");
        }
    }

    wtxNew.BindWallet(wallet);
    wtxNew.fFromMe = true;
    *static_cast<CTransaction *>(&wtxNew) = CTransaction(tx);
    // I'll manage my own keys because I have multiple.  Passing a valid key down breaks layering.
    CReserveKey dummy(wallet);
    if (!wallet->CommitTransaction(wtxNew, dummy))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the "
                                             "coins in your wallet were already spent, such as if you used a copy of "
                                             "wallet.dat and coins were spent in the copy but not marked as spent "
                                             "here.");

    feeChangeKeyReservation.KeepKey();
    groupChangeKeyReservation.KeepKey();
}


void GroupMelt(CWalletTx &wtxNew, const CTokenGroupID &grpID, CAmount totalNeeded, CWallet *wallet)
{
    const std::vector<CRecipient> outputs; // Melt has no outputs (except change)
    CAmount totalAvailable = 0;
    LOCK2(cs_main, wallet->cs_wallet);

    // Find meltable coins
    std::vector<COutput> coins;
    wallet->FilterCoins(coins, [grpID](const CWalletTx *tx, const CTxOut *out) {
        CTokenGroupPair tg = GetTokenGroupPair(out->scriptPubKey);
        // must be a grouped output sitting in group address
        return ((grpID == tg.associatedGroup) && (grpID == tg.mintMeltGroup));
    });

    // Get a near but greater quantity
    std::vector<COutput> chosenCoins;
    totalAvailable = GroupCoinSelection(coins, totalNeeded, chosenCoins);

    if (totalAvailable < totalNeeded)
    {
        std::string strError;
        strError =
            strprintf("Not enough tokens in the controlling address.  Need %d more.", totalNeeded - totalAvailable);
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
    }

    // by passing a nonzero totalNeeded, but empty outputs, there is a surplus number of tokens.
    // This surplus will be melted.
    ConstructTx(wtxNew, chosenCoins, outputs, totalAvailable, totalNeeded, grpID, wallet);
}

void GroupSend(CWalletTx &wtxNew,
    const CTokenGroupID &grpID,
    const std::vector<CRecipient> &outputs,
    CAmount totalNeeded,
    CWallet *wallet)
{
    LOCK2(cs_main, wallet->cs_wallet);
    std::string strError;
    std::vector<COutput> coins;
    CAmount totalAvailable = 0;
    wallet->FilterCoins(coins, [grpID, &totalAvailable](const CWalletTx *tx, const CTxOut *out) {
        CTokenGroupPair tg = GetTokenGroupPair(out->scriptPubKey);
        if (grpID == tg.associatedGroup)
            totalAvailable += tg.quantity;
        return grpID == tg.associatedGroup; // must be sitting in group address
    });

    if (totalAvailable < totalNeeded)
    {
        strError = strprintf("Not enough tokens.  Need %d more.", totalNeeded - totalAvailable);
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
    }

    // Get a near but greater quantity
    std::vector<COutput> chosenCoins;
    totalAvailable = GroupCoinSelection(coins, totalNeeded, chosenCoins);

    ConstructTx(wtxNew, chosenCoins, outputs, totalAvailable, totalNeeded, grpID, wallet);
}


extern UniValue token(const UniValue &params, bool fHelp)
{
    CWallet *wallet = pwalletMain;
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 1)
        throw std::runtime_error(
            "token [new, mint, melt, send] \n"
            "\nToken functions.\n"
            "new creates a new token type.\n"
            "mint creates new tokens. args: groupId address quantity\n"
            "singlemint creates a new group and limited quantity of tokens. args: address quantity [address "
            "quantity...]\n"
            "melt removes tokens from circulation. args: groupId quantity\n"
            "balance reports quantity of this token. args: groupId [address]\n"
            "send sends tokens to a new address. args: groupId address quantity [address quantity...]\n"
            "\nArguments:\n"
            "1. \"groupId\"     (string, required) the group identifier\n"
            "2. \"address\"     (string, required) the destination address\n"
            "3. \"quantity\"    (numeric, required) the quantity desired\n"
            "\nResult:\n"
            "\n"
            "\nExamples:\n"
            "\nCreate a transaction with no inputs\n" +
            HelpExampleCli("createrawtransaction", "\"[]\" \"{\\\"myaddress\\\":0.01}\"") +
            "\nAdd sufficient unsigned inputs to meet the output value\n" +
            HelpExampleCli("fundrawtransaction", "\"rawtransactionhex\"") + "\nSign the transaction\n" +
            HelpExampleCli("signrawtransaction", "\"fundedtransactionhex\"") + "\nSend the transaction\n" +
            HelpExampleCli("sendrawtransaction", "\"signedtransactionhex\""));

    std::string operation;
    std::string p0 = params[0].get_str();
    std::transform(p0.begin(), p0.end(), std::back_inserter(operation), ::tolower);
    EnsureWalletIsUnlocked();

    if (operation == "new")
    {
        std::string account = "";
        CPubKey newKey;
        if (!wallet->GetKeyFromPool(newKey))
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
        CKeyID keyID = newKey.GetID();
        wallet->SetAddressBook(keyID, account, "receive");
        CTokenGroupID grpID(keyID);
        UniValue ret(UniValue::VOBJ);
        ret.push_back(Pair("groupIdentifier", grpID.Encode()));
        ret.push_back(Pair("controllingAddress", EncodeDestination(keyID)));
        return ret;
    }
    else if (operation == "singlemint")
    {
        unsigned int curparam = 1;
        CAmount totalValue = 0;

        CCoinControl coinControl;
        coinControl.fAllowOtherInputs = true; // Allow a normal bitcoin input for change
        COutput coin(nullptr, 0, 0, false);

        {
            // I can use any prevout for the singlemint operation, so find some dust
            std::vector<COutput> coins;
            CAmount lowest = MAX_MONEY;
            wallet->FilterCoins(coins, [&lowest](const CWalletTx *tx, const CTxOut *out) {
                CTokenGroupPair tg = GetTokenGroupPair(out->scriptPubKey);
                // although its possible to spend a grouped input to produce
                // a single mint group, I won't allow it to make the tx construction easier.
                if ((tg.associatedGroup == NoGroup) && (out->nValue < lowest))
                {
                    lowest = out->nValue;
                    return true;
                }
                return false;
            });

            if (0 == coins.size())
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "No available outputs");
            }
            coin = coins[coins.size() - 1];
        }

        CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
        hasher << coin.GetOutPoint();
        CTokenGroupID grpID(hasher.GetHash());
        coinControl.Select(coin.GetOutPoint());

        std::vector<CRecipient> outputs;
        outputs.reserve(params.size() / 2);
        while (curparam + 1 < params.size())
        {
            CTxDestination dst = DecodeDestination(params[curparam].get_str(), Params());
            if (dst == CTxDestination(CNoDestination()))
            {
                throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: destination address");
            }
            CAmount amount = AmountFromIntegralValue(params[curparam + 1]);
            if (amount <= 0)
                throw JSONRPCError(RPC_TYPE_ERROR, "Invalid parameter: amount");
            CScript script = GetScriptForDestination(dst, grpID, amount);
            CRecipient recipient = {script, GROUPED_SATOSHI_AMT, false};
            totalValue += amount;
            outputs.push_back(recipient);
            curparam += 2;
        }

        CWalletTx wtx;
        CReserveKey reservekey(wallet);
        CAmount nFeeRequired = 0;
        int nChangePosRet = -1;
        std::string strError;
        if (!wallet->CreateTransaction(outputs, wtx, reservekey, nFeeRequired, nChangePosRet, strError, &coinControl))
        {
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its "
                                 "amount, complexity, or use of recently received funds!",
                FormatMoney(nFeeRequired));
            throw JSONRPCError(RPC_WALLET_ERROR, strError);
        }
        if (!wallet->CommitTransaction(wtx, reservekey))
            throw JSONRPCError(RPC_WALLET_ERROR,
                "Error: The transaction was rejected! This might happen if some of the "
                "coins in your wallet were already spent, such as if you used a copy of "
                "wallet.dat and coins were spent in the copy but not marked as spent "
                "here.");

        UniValue ret(UniValue::VOBJ);
        ret.push_back(Pair("groupIdentifier", grpID.Encode()));
        ret.push_back(Pair("transaction", wtx.GetHash().GetHex()));
        return ret;
    }
    else if (operation == "mint")
    {
        CTokenGroupID grpID;
        CAmount totalNeeded = 0;
        unsigned int curparam = 1;
        std::vector<CRecipient> outputs;
        curparam = ParseGroupAddrValue(params, curparam, grpID, outputs, totalNeeded, true);

        if (!wallet->HaveTxDestination(grpID.ControllingAddress()))
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter 1: Group is not owned by this wallet");
        }

        if (outputs.empty())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "No destination address or payment amount");
        }
        if (curparam != params.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Improper number of parameters, did you forget the payment amount?");
        }

        CWalletTx wtx;
        CReserveKey reservekey(wallet);
        CCoinControl coinControl;
        coinControl.fAllowOtherInputs = true; // Allow a normal bitcoin input for change
        CAmount nFeeRequired = 0;
        int nChangePosRet = -1;
        std::string strError;

        CTxDestination mintableAddress = grpID.ControllingAddress();
        // Find mintable coins
        std::vector<COutput> coins;
        int nOptions = wallet->FilterCoins(coins, [grpID](const CWalletTx *tx, const CTxOut *out) {
            CTokenGroupPair tg = GetTokenGroupPair(out->scriptPubKey);
            if (tg.associatedGroup != NoGroup)
                return false; // need bitcoin only
            return grpID == tg.mintMeltGroup; // must be sitting in group address
        });
        if (nOptions == 0)
        {
            strError = strprintf("To mint coins, first send %s to the group's controlling address.", CURRENCY_UNIT);
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
        }
        CAmount totalAvailable = 0;
        for (auto coin : coins)
        {
            totalAvailable += coin.tx->vout[coin.i].nValue;
        }
        if (totalAvailable == 0)
        {
            strError = strprintf("Minting requires that an output in the group's controlling address be spent.",
                totalNeeded - totalAvailable);
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strError);
        }
        std::vector<COutput> chosenCoins;
        CoinSelection(coins, GROUPED_SATOSHI_AMT, chosenCoins);
        for (const auto &c : chosenCoins)
        {
            coinControl.Select(COutPoint(c.tx->GetHash(), c.i));
        }

        if (!wallet->CreateTransaction(outputs, wtx, reservekey, nFeeRequired, nChangePosRet, strError, &coinControl))
        {
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its "
                                 "amount, complexity, or use of recently received funds!",
                FormatMoney(nFeeRequired));
            throw JSONRPCError(RPC_WALLET_ERROR, strError);
        }
        if (!wallet->CommitTransaction(wtx, reservekey))
            throw JSONRPCError(RPC_WALLET_ERROR,
                "Error: The transaction was rejected! This might happen if some of the "
                "coins in your wallet were already spent, such as if you used a copy of "
                "wallet.dat and coins were spent in the copy but not marked as spent "
                "here.");
        return wtx.GetHash().GetHex();
    }
    else if (operation == "balance")
    {
        if (params.size() > 3)
        {
            throw std::runtime_error("Invalid number of argument to token balance");
        }
        if (params.size() == 1) // no group specified, show them all
        {
            std::unordered_map<CTokenGroupID, CAmount> balances;
            GetAllGroupBalances(wallet, balances);
            UniValue ret(UniValue::VOBJ);
            for (const auto &item : balances)
            {
                ret.push_back(Pair(item.first.Encode(), item.second));
            }
            return ret;
        }
        CTokenGroupID grpID(params[1].get_str());
        if (!grpID.isUserGroup())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter 1: No group specified");
        }
        CTxDestination dst;
        if (params.size() > 2)
        {
            dst = DecodeDestination(params[2].get_str(), Params());
        }
        return UniValue(GetGroupBalance(grpID, dst, wallet));
    }
    else if (operation == "send")
    {
        CTokenGroupID grpID;
        CAmount totalNeeded = 0;
        unsigned int curparam = 1;
        std::vector<CRecipient> outputs;
        curparam = ParseGroupAddrValue(params, curparam, grpID, outputs, totalNeeded, true);

        if (outputs.empty())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "No destination address or payment amount");
        }
        if (curparam != params.size())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Improper number of parameters, did you forget the payment amount?");
        }
        CWalletTx wtx;
        GroupSend(wtx, grpID, outputs, totalNeeded, wallet);
        return wtx.GetHash().GetHex();
    }
    else if (operation == "melt")
    {
        CTokenGroupID grpID;
        std::vector<CRecipient> outputs;

        grpID = CTokenGroupID(params[1].get_str());
        if (!grpID.isUserGroup())
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid parameter: No group specified");
        }

        CAmount totalNeeded = AmountFromIntegralValue(params[2]);

        if (!wallet->HaveTxDestination(grpID.ControllingAddress()))
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Group is not owned by this wallet");
        }

        CWalletTx wtx;
        GroupMelt(wtx, grpID, totalNeeded, wallet);
        return wtx.GetHash().GetHex();
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Unknown group operation");
    }
    return NullUniValue;
}
