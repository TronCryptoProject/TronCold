package org.tron.walletcli;

import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.InvalidProtocolBufferException;
import com.typesafe.config.Config;
import javafx.util.Pair;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;
import org.tron.api.GrpcAPI;
import org.tron.api.GrpcAPI.AccountList;
import org.tron.api.GrpcAPI.AssetIssueList;
import org.tron.api.GrpcAPI.NodeList;
import org.tron.api.GrpcAPI.WitnessList;
import org.tron.api.GrpcAPI.Node;
import org.tron.common.crypto.ECKey;
import org.tron.common.utils.*;
import org.tron.core.config.Configuration;
import org.tron.protos.Contract;
import org.tron.protos.Protocol;
import org.tron.protos.Protocol.Account;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.Transaction;
import org.tron.walletserver.WalletClient;
import org.tron.common.utils.ByteUtil;
import org.apache.commons.io.*;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;

import static org.tron.common.crypto.Hash.sha256;


class TxComp implements Comparator<Map<String,String>>{
	private String compkey;
	public TxComp(String compkey){
		this.compkey = compkey;
	}
	public int compare(Map<String,String> map1 ,Map<String,String> map2){
		if (map1.containsKey(compkey) && map2.containsKey(compkey)){
			String val1 = map1.get(compkey);
			String val2 = map2.get(compkey);
			return val1.compareTo(val2);
		}
		return -1;
	}
}

public class TronClient {

  private static final Logger logger = LoggerFactory.getLogger("TronClient");
  private WalletClient wallet;
  private HashMap<String, ArrayList<HashMap<String,String>>> tx_map = new HashMap<>();
  public static final String FAILED = "failed";
  public static final String SUCCESS = "success";


  public JSONObject registerWallet(String password, String accountName) {
	  JSONObject json_obj = new JSONObject();
	  if (!WalletClient.passwordValid(password)) {
		  json_obj.put("result", FAILED);
		  json_obj.put("reason", "Password is not valid.");
	  }else{
		  wallet = new WalletClient(true);
		  wallet.store(password);
		  wallet.setAccountName(accountName);
		  wallet.setPDirty(password);

		  json_obj.put("result", SUCCESS);
		  json_obj.put("privAddress", wallet.getPrivateKey());
		  json_obj.put("passcode", password);
		  json_obj.put("accountName", wallet.getAccountName());
          json_obj.put("pubAddress", WalletClient.encode58Check(wallet.getAddress()));
	  }

	  return json_obj;
  }

  public JSONObject createPaperWallet() {
		JSONObject json_obj = new JSONObject();
		WalletClient wallet = new WalletClient(true);

		json_obj.put("result", SUCCESS);
		json_obj.put("privAddress", wallet.getPrivateKey());
		json_obj.put("pubAddress", WalletClient.encode58Check(wallet.getAddress()));
		return json_obj;
  }

  public JSONObject importWallet(String password, String priKey) {
		JSONObject json_obj = new JSONObject();
		if (!WalletClient.passwordValid(password)) {
			json_obj.put("result", FAILED);
			json_obj.put("reason", "Password is not valid.");
		  	return json_obj;
		}
		if (!WalletClient.priKeyValid(priKey)){
			json_obj.put("result", FAILED);
            json_obj.put("reason", "Private key is not valid.");
		  	return json_obj;
		}
		wallet = new WalletClient(priKey);
		if (wallet.getEcKey() == null) {
			json_obj.put("result", FAILED);
            json_obj.put("reason", "Unable to get wallet using private key");
		  	return json_obj;
		}

		wallet.store(password);
		json_obj.put("result", SUCCESS);
		json_obj.put("accountName", wallet.getAccountName());
		json_obj.put("pubAddress", WalletClient.encode58Check(wallet.getAddress()));
		json_obj.put("pdirty", wallet.isPDirty());
		return json_obj;
  }


  public JSONObject login(String password) {
  	JSONObject json_obj = new JSONObject();

	if (!WalletClient.passwordValid(password)) {
	    json_obj.put("result", FAILED);
        json_obj.put("reason", "Password is not valid.");
	  return json_obj;
	}
	if (wallet == null) {
	  wallet = WalletClient.GetWalletByStorage(password);
	  if (wallet == null) {
          json_obj.put("result", FAILED);
          json_obj.put("reason", "You need to register or import wallet before logging in.");
          return json_obj;
	  }
	}

	if (wallet.login(password)){
	    json_obj.put("result", SUCCESS);
	    json_obj.put("accountName", wallet.getAccountName());
	    json_obj.put("pubAddress", WalletClient.encode58Check(wallet.getAddress()));
    }else{
	    json_obj.put("result", FAILED);
        json_obj.put("reason", "Login failed because something is wrong with the password.");
    }
    return json_obj;
  }

  public JSONObject logout() {
      JSONObject json_obj = new JSONObject();
	if (wallet != null) {
	    wallet.logout();
        json_obj.put("result", SUCCESS);
	}else{
        json_obj.put("result", FAILED);
        json_obj.put("reason", "Unable to logout from wallet.");
    }
    return json_obj;
  }


  public JSONObject backupWallet(String password) {
      JSONObject json_obj = new JSONObject();

	if (wallet == null || !wallet.isLoginState()) {
        json_obj.put("result", FAILED);
        json_obj.put("reason", "Not logged in!");
	    return json_obj;
	}
	if (!WalletClient.passwordValid(password)) {
        json_obj.put("result", FAILED);
        json_obj.put("reason", "Invalid password!");
        return json_obj;
	}

	if (!WalletClient.checkPassWord(password)) {
        json_obj.put("result", FAILED);
        json_obj.put("reason", "Wrong password!");
        return json_obj;
	}

	if (wallet.getEcKey() == null || wallet.getEcKey().getPrivKey() == null) {
	  wallet = WalletClient.GetWalletByStorage(password);
	  if (wallet == null) {
          json_obj.put("result", FAILED);
          json_obj.put("reason", "No backup found!");
          return json_obj;
	  }
	}
	ECKey ecKey = wallet.getEcKey();
	byte[] privKeyPlain = ecKey.getPrivKeyBytes();
	String priKey = ByteArray.toHexString(privKeyPlain);

	json_obj.put("result", SUCCESS);
	json_obj.put("privAddress", priKey);
	json_obj.put("pubAddress",WalletClient.encode58Check(wallet.getAddress()));
	json_obj.put("password", password);
	json_obj.put("accountName", wallet.getAccountName());

	return json_obj;
  }


  public JSONObject prepareTransaction(String toAddress, long amount){
      JSONObject json_obj = new JSONObject();
	if (wallet == null || !wallet.isLoginState()) {
        json_obj.put("result", FAILED);
        json_obj.put("reason", "Unable to create transaction. Please login in first.");
	  return json_obj;
	}

	byte[] to = WalletClient.decodeFromBase58Check(toAddress);
	if (to == null) {
        json_obj.put("result", FAILED);
        json_obj.put("reason", "Recipient address is invalid!");
	  return json_obj;
	}


	Transaction res_tx = wallet.prepareTransaction(to, amount);
	if (res_tx == null){
        json_obj.put("result", FAILED);
        json_obj.put("reason", "Prepare transaction failed.");
	}else{
	  byte[] data_bytes = new byte[res_tx.getSerializedSize()];

	  try{
		  res_tx.writeTo(CodedOutputStream.newInstance(data_bytes));
	  }catch (IOException e) {
          json_obj.put("result", FAILED);
          json_obj.put("reason", "Transaction write failed: " + e.getMessage());
		  return json_obj;
	  }

	  if (res_tx.hasRawData()){
	  	  json_obj.put("data", ByteUtil.toHexString(data_bytes));
		  json_obj.put("timestamp", res_tx.getRawData().getTimestamp());
		  json_obj.put("refblocknum", res_tx.getRawData().getRefBlockNum());
		  json_obj.put("from", WalletClient.encode58Check(wallet.getAddress()));
		  json_obj.put("to", toAddress);
		  json_obj.put("amount", amount);

		  JSONArray json_sigs = new JSONArray();
		  for(ByteString bs : res_tx.getSignatureList()){
			  json_sigs.add(Hex.toHexString(bs.toByteArray()));
		  }
		  json_obj.put("signatures", json_sigs);


		String result = "";
		long totalfee = 0;

		for (Transaction.Result r : res_tx.getRetList()){
			totalfee += r.getFee();
			if (r.getRetValue() == 1){
				result = FAILED;
			}else if (r.getRetValue() != 0 && !result.equals(FAILED)){
				result = "pending";
			}
		}
		if (result.equals("")) result = SUCCESS;

		json_obj.put("fee", totalfee);
		json_obj.put("result", SUCCESS);
		json_obj.put("status", result);
		json_obj.put("txhash", ByteUtil.toHexString(TransactionUtils.getHash(res_tx)));
	  }else{
		json_obj.put("result", FAILED);
		json_obj.put("reason", "Created transaction does not have raw data.");
	  }
	}

	return json_obj;
  }

  public JSONObject getSignTxInfo(String hextx) {
      JSONObject json_obj = new JSONObject();

	  byte[] tx_byte = Hex.decode(hextx);
	  Transaction transaction;
	  try{
		  transaction = Transaction.parseFrom(tx_byte);
	  }catch(InvalidProtocolBufferException e){
	      json_obj.put("result", FAILED);
	      json_obj.put("reason", "Unable to parse transaction: " + e.getMessage());
		  return json_obj;
	  }


	  if (transaction.hasRawData()){

		  try{
		  	  long timestamp = transaction.getRawData().getTimestamp();
		  	  if (timestamp == 0){
				  json_obj.put("timestamp", "");
			  }else{
				  Date date = new Date(timestamp);
				  SimpleDateFormat df = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss zzz");
				  json_obj.put("timestamp", df.format(date));
			  }

			  json_obj.put("refblocknum", transaction.getRawData().getRefBlockNum());

			  Transaction.Contract contract =  transaction.getRawData().getContract(0);
			  final Contract.TransferContract transferContract = contract.getParameter().
					  unpack(Contract.TransferContract.class);
			  final byte[] addressBytes = transferContract.getOwnerAddress().toByteArray();
			  final String addressHex = WalletClient.encode58Check(addressBytes);
			  final byte[] toAddressBytes = transferContract.getToAddress().toByteArray();
			  final String toAddressHex = WalletClient.encode58Check(toAddressBytes);
			  final long amount = transferContract.getAmount();

			  json_obj.put("from", addressHex);
			  json_obj.put("to", toAddressHex);
			  json_obj.put("amount", amount);

		  }catch(InvalidProtocolBufferException e){
              json_obj.put("result", FAILED);
              json_obj.put("reason", "Unable to fetch transaction contract details.");
              return json_obj;
		  }

		  JSONArray json_sigs = new JSONArray();
		  for(ByteString bs : transaction.getSignatureList()){
			  json_sigs.add(Hex.toHexString(bs.toByteArray()));
		  }
		  json_obj.put("signatures", json_sigs);


		  String result = "";
		  long totalfee = 0;

		  for (Transaction.Result r : transaction.getRetList()){
			  totalfee += r.getFee();
			  if (r.getRetValue() == 1){
				  result = FAILED;
			  }else if (r.getRetValue() != 0 && !result.equals(FAILED)){
				  result = "pending";
			  }
		  }
		  if (result.equals("")) result = SUCCESS;

		  json_obj.put("fee", totalfee);
		  json_obj.put("data", hextx);
		  json_obj.put("result", SUCCESS);
		  json_obj.put("status", result);
		  json_obj.put("txhash", ByteUtil.toHexString(TransactionUtils.getHash(transaction)));
	  }else{
          json_obj.put("result", FAILED);
          json_obj.put("reason", "Imported transaction does not have raw data.");
	  }

	  return json_obj;
  }

  public JSONObject signTransaction(String hextx) {
      JSONObject json_obj = new JSONObject();

	if (wallet == null || !wallet.isLoginState()) {
        json_obj.put("result", FAILED);
        json_obj.put("reason", "Unable to sign transaction. Please login in first.");
	    return json_obj;
	}

	if (hextx == null || hextx.equals("")){
        json_obj.put("result", FAILED);
        json_obj.put("reason", "Transaction is null, nothing to sign!");
        return json_obj;
	}

	byte[] tx_byte = Hex.decode(hextx);
	Transaction transaction;
	try{
		transaction = Transaction.parseFrom(tx_byte);
	}catch(InvalidProtocolBufferException e){
        json_obj.put("result", FAILED);
        json_obj.put("reason", "Transaction parsing failed: " + e.getMessage());
        return json_obj;
	}

	Transaction res_tx = wallet.signTransaction(transaction);

	if (res_tx == null){
        json_obj.put("result", FAILED);
        json_obj.put("reason", "Could not sign transaction.");
        return json_obj;
	}else{
	   
	  byte[] data_bytes = new byte[res_tx.getSerializedSize()];
	  try{
		  res_tx.writeTo(CodedOutputStream.newInstance(data_bytes));
	  }catch (IOException e){
          json_obj.put("result", FAILED);
          json_obj.put("reason", "Signed transaction write failed: " + e.getMessage());
          return json_obj;
	  }


	  if (res_tx.hasRawData()){

		try{
			json_obj.put("data", ByteUtil.toHexString(data_bytes));
			json_obj.put("timestamp", res_tx.getRawData().getTimestamp());
			json_obj.put("refblocknum", res_tx.getRawData().getRefBlockNum());

			Transaction.Contract contract =  res_tx.getRawData().getContract(0);

			final Contract.TransferContract transferContract = contract.getParameter().
					unpack(Contract.TransferContract.class);
			final byte[] addressBytes = transferContract.getOwnerAddress().toByteArray();
			final String addressHex = WalletClient.encode58Check(addressBytes);
			final byte[] toAddressBytes = transferContract.getToAddress().toByteArray();
			final String toAddressHex = WalletClient.encode58Check(toAddressBytes);
			final long amount = transferContract.getAmount();

			json_obj.put("from", addressHex);
			json_obj.put("to", toAddressHex);
			json_obj.put("amount", amount);

		}catch(InvalidProtocolBufferException e){
            json_obj.put("result", FAILED);
            json_obj.put("reason", "Unable to fetch transaction contract details: " + e.getMessage());
            return json_obj;
		}

		JSONArray json_sigs = new JSONArray();
		for(ByteString bs : res_tx.getSignatureList()){
			json_sigs.add(Hex.toHexString(bs.toByteArray()));
		}
		json_obj.put("signatures", json_sigs);

		String result = "";
		long totalfee = 0;

		for (Transaction.Result r : res_tx.getRetList()){
			totalfee += r.getFee();
			if (r.getRetValue() == 1){
				result = FAILED;
			}else if (r.getRetValue() != 0 && !result.equals(FAILED)){
				result = "pending";
			}
		}
		if (result.equals("")) result = SUCCESS;

		json_obj.put("fee", totalfee);

		json_obj.put("result", SUCCESS);
		json_obj.put("status", result);
		json_obj.put("txhash", ByteUtil.toHexString(TransactionUtils.getHash(res_tx)));

		JSONObject tx_obj = new JSONObject();
		tx_obj.put("from", json_obj.get("from"));
		tx_obj.put("to", json_obj.get("to"));
		tx_obj.put("amount", json_obj.get("amount"));

		Date date = new Date((Long)json_obj.get("timestamp"));
		SimpleDateFormat df = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss zzz");
		json_obj.put("timestamp", df.format(date));
		tx_obj.put("timestamp", df.format(date));

		System.out.println("timestamp long: " + json_obj.get("timestamp"));
		System.out.println("timestamp: " + df.format(date));
		wallet.addSignedTransaction(tx_obj);

	  }else{
          json_obj.put("result", FAILED);
          json_obj.put("reason", "Imported transaction does not have raw data.");
	  }
	}

	return json_obj;
  }


  public JSONObject getTransactions(String userAddress){
	  JSONObject json_obj = new JSONObject();

	  if (wallet == null || !wallet.isLoginState()) {
		  json_obj.put("result", FAILED);
		  json_obj.put("reason", "Unable to get transactions. Please login in first.");
		  return json_obj;
	  }

	  String pubAddress = WalletClient.encode58Check(wallet.getAddress());
	  if (pubAddress.equals(userAddress)){
		  json_obj.put("result" ,SUCCESS);
		  json_obj.put("txs",  wallet.getSignedTransactions());

	  }else {
		  json_obj.put("result", FAILED);
		  json_obj.put("reason", "Wallet is not configured for this address");
	  }

	  return json_obj;
  }

  public JSONObject validatePasscodeImport(String password, boolean tostore){
  	  JSONObject json_obj = new JSONObject();

	  if (!WalletClient.passwordValid(password)) {
		  json_obj.put("result", FAILED);
		  json_obj.put("reason", "Password invalid!");
		  return json_obj;
	  }

	  if (wallet == null) {
		  json_obj.put("result", FAILED);
		  json_obj.put("reason", "Import unsuccessful!");
		  return json_obj;
	  }

	  if (!wallet.isPDirty()) {
		  json_obj.put("result", FAILED);
		  json_obj.put("reason", "Cannot validate passcode!");
		  return json_obj;
	  }

	  if (!wallet.checkPassWordWithAccess(password)) {
		  json_obj.put("result", FAILED);
		  json_obj.put("reason", "Wrong password!");
		  return json_obj;
	  }
	  json_obj.put("result", SUCCESS);

	  if (tostore){
	  	wallet.store(password);
	  }
	  return json_obj;
  }

  public JSONObject isPDirty(){
  	JSONObject json_obj = new JSONObject();
  	if (wallet == null){
		json_obj.put("result", FAILED);
		json_obj.put("reason", "Wallet is not configured!");
		return json_obj;
	}
	json_obj.put("result", SUCCESS);
  	json_obj.put("pdirty", wallet.isPDirty());
  	return json_obj;
  }
}
