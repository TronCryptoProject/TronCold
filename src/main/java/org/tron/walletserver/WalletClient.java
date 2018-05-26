package org.tron.walletserver;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.typesafe.config.Config;
import com.typesafe.config.ConfigObject;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;
import org.tron.api.GrpcAPI;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.Hash;
import org.tron.common.crypto.SymmEncoder;
import org.tron.common.utils.Base58;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.FileUtil;
import org.tron.common.utils.TransactionUtils;
import org.tron.common.utils.Utils;
import org.tron.core.config.Configuration;
import org.tron.core.config.Parameter.CommonConstant;
import org.tron.protos.Contract;
import org.tron.protos.Protocol.Account;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.Witness;
import org.tron.walletcli.Encryption;
import sun.security.jca.JCAUtil;

import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

class AccountComparator implements Comparator {

  public int compare(Object o1, Object o2) {
    return Long.compare(((Account) o2).getBalance(), ((Account) o1).getBalance());
  }
}

class WitnessComparator implements Comparator {

  public int compare(Object o1, Object o2) {
    return Long.compare(((Witness) o2).getVoteCount(), ((Witness) o1).getVoteCount());
  }
}

public class WalletClient {

  private static final Logger logger = LoggerFactory.getLogger("WalletClient");
  private static String FilePath = "store";
  private ECKey ecKey = null;
  private boolean loginState = false;
  private Encryption encryption;

  {
    try{
      InputStream inputStream = getClass().getResourceAsStream("/tronks.ks");
      String data = FileUtil.readFromInputStream(inputStream);
      encryption = new Encryption(data.trim());
    }catch (Exception e){}
  }


  /**
   * Creates a new WalletClient with a random ECKey or no ECKey.
   */
  public WalletClient(boolean genEcKey) {
    if (genEcKey) {
      this.ecKey = new ECKey(Utils.getRandom());
    }
  }

  //  Create Wallet with a pritKey
  public WalletClient(String priKey) {
    ECKey temKey = null;
    try {
      BigInteger priK = new BigInteger(priKey, 16);
      temKey = ECKey.fromPrivate(priK);
    } catch (Exception ex) {
      ex.printStackTrace();
    }
    this.ecKey = temKey;
  }

  public boolean login(String password) {
    loginState = checkPassWord(password);
    return loginState;
  }

  public boolean isLoginState() {
    return loginState;
  }

  public void logout() {
    loginState = false;
  }

  /**
   * Get a Wallet from storage
   */
  public static WalletClient GetWalletByStorage(String password) {
    byte[] priKeyEnced = loadPriKey();
    if (ArrayUtils.isEmpty(priKeyEnced)) {
      return null;
    }
    //dec priKey
    byte[] salt0 = loadSalt0();
    byte[] aesKey = getEncKey(password, salt0);
    byte[] priKeyHexPlain = SymmEncoder.AES128EcbDec(priKeyEnced, aesKey);
    String priKeyPlain = Hex.toHexString(priKeyHexPlain);

    return new WalletClient(priKeyPlain);
  }

  /**
   * Creates a Wallet with an existing ECKey.
   */

  public WalletClient(final ECKey ecKey) {
    this.ecKey = ecKey;
  }

  public ECKey getEcKey() {
    return ecKey;
  }

  public byte[] getAddress() {
    return ecKey.getAddress();
  }

  public String getPrivateKey() {
    byte[] privKeyPlain = ecKey.getPrivKeyBytes();
    return ByteArray.toHexString(privKeyPlain);
  }

  public String getAccountName(){
    String file_encrypt = getFileEncryptData();
    String res_str = new String();

    if (file_encrypt != null && !file_encrypt.equals("")){
      JSONObject json_obj = encryption.decryptObject(file_encrypt);
      String pubAddress = encode58Check(getAddress());

      if (json_obj.containsKey(pubAddress)){
        JSONObject inner_obj = (JSONObject) json_obj.get(pubAddress);
        if (inner_obj.containsKey("accountName")){
          res_str = (String) inner_obj.get("accountName");
        }
      }
    }

    return res_str;
  }

  public void setAccountName(String accName){
    JSONObject json_obj = encryption.decryptObject(getFileEncryptData());
    String pubAddress = encode58Check(getAddress());
    JSONObject inner_obj = new JSONObject();
    if (json_obj.containsKey(pubAddress)){
      inner_obj = (JSONObject) json_obj.get(pubAddress);
    }
    inner_obj.put("accountName", accName);
    json_obj.put(pubAddress, inner_obj);

    String encrypted_str = encryption.encryptObject(json_obj);
    writeEncryptData(encrypted_str.getBytes());
  }

  public boolean isPDirty(){
    String file_encrypt = getFileEncryptData();

    if (file_encrypt != null && !file_encrypt.equals("")) {
      JSONObject json_obj = encryption.decryptObject(file_encrypt);
      String pubAddress = encode58Check(getAddress());

      if (json_obj.containsKey(pubAddress)) {
        JSONObject inner_obj = (JSONObject)json_obj.get(pubAddress);
        if (inner_obj.containsKey("pwd")){
          String p = (String) inner_obj.get("pwd");
          if (p != null && !p.equals("") && passwordValid(p)){
            return true;
          }
        }
      }
    }

    return false;
  }

  public void setPDirty(String p){
    String file_encrypt = getFileEncryptData();
    JSONObject inner_obj = new JSONObject();
    JSONObject json_obj = new JSONObject();

    if (file_encrypt != null && !file_encrypt.equals("")) {
      json_obj = encryption.decryptObject(file_encrypt);
      String pubAddress = encode58Check(getAddress());

      if (json_obj.containsKey(pubAddress)) {
        inner_obj = (JSONObject)json_obj.get(pubAddress);
      }
    }
    inner_obj.put("pwd",p);
    json_obj.put(encode58Check(getAddress()), inner_obj);

    String encrypted_str = encryption.encryptObject(json_obj);
    writeEncryptData(encrypted_str.getBytes());
  }

  public boolean checkPassWordWithAccess(String pass){
    String file_encrypt = getFileEncryptData();

    if (file_encrypt != null && !file_encrypt.equals("")) {
      JSONObject json_obj = encryption.decryptObject(file_encrypt);
      String pubAddress = encode58Check(getAddress());

      if (json_obj.containsKey(pubAddress)) {
        JSONObject inner_obj = (JSONObject)json_obj.get(pubAddress);
        if (inner_obj.containsKey("pwd")) {
          String p = (String) inner_obj.get("pwd");
          System.out.println("database pwd: " + p);
          System.out.println("input pwd: " + pass);
          if (p != null && !p.equals("") && passwordValid(p) && p.equals(pass)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  public JSONArray getSignedTransactions(){
    String file_encrypt = getFileEncryptData();
    JSONArray res_arr = new JSONArray();

    if (file_encrypt != null && !file_encrypt.equals("")) {
      JSONObject json_obj = encryption.decryptObject(file_encrypt);
      String pubAddress = encode58Check(getAddress());

      if (json_obj.containsKey(pubAddress)) {
        JSONObject inner_obj = (JSONObject) json_obj.get(pubAddress);
        if (inner_obj.containsKey("signedTxs")) {
          res_arr = (JSONArray) inner_obj.get("signedTxs");
        }
      }
    }
    return res_arr;
  }

  public void addSignedTransaction(JSONObject tx_json_obj){
    JSONObject json_obj = encryption.decryptObject(getFileEncryptData());
    String pubAddress = encode58Check(getAddress());
    JSONArray res_arr = new JSONArray();

    if (json_obj.containsKey(pubAddress)){
      JSONObject inner_obj = (JSONObject) json_obj.get(pubAddress);
      if (inner_obj.containsKey("signedTxs")){
        res_arr = (JSONArray) inner_obj.get("signedTxs");
      }else{
        inner_obj.put("signedTxs", new JSONArray());
        json_obj.put(pubAddress, inner_obj);
      }
    }else{
      json_obj.put(pubAddress, new JSONObject());
    }

    res_arr.add(0, tx_json_obj);

    JSONObject inner_obj = (JSONObject)json_obj.get(pubAddress);
    inner_obj.put("signedTxs", res_arr);
    json_obj.put(pubAddress, inner_obj);

    String encrypted_str = encryption.encryptObject(json_obj);
    writeEncryptData(encrypted_str.getBytes());
  }

  private static String getFileEncryptData(){
    try {
      File file = new File("access");
      FileInputStream fs = new FileInputStream(file);
      byte[] str = new byte[(int) file.length()];
      fs.read(str);
      fs.close();
      return new String(str);
    }catch (Exception e){}
    return new String();
  }

  private void writeEncryptData(byte[] bytes){
    try{
      File file = new File("access");
      FileOutputStream fos = new FileOutputStream(file);
      fos.write(bytes);
      fos.close();
    }catch(IOException e){}
  }

  public void store(String password) {
    if (ecKey == null || ecKey.getPrivKey() == null) {
      logger.warn("Warning: Store wallet failed, PrivKey is null !!");
      return;
    }

    byte[] salt0 = new byte[16];
    byte[] salt1 = new byte[16];
    JCAUtil.getSecureRandom().nextBytes(salt0);
    JCAUtil.getSecureRandom().nextBytes(salt1);
    byte[] aseKey = getEncKey(password, salt0);
    byte[] pwd = getPassWord(password, salt1);
    byte[] privKeyPlain = ecKey.getPrivKeyBytes();
    System.out.println("privKey:" + ByteArray.toHexString(privKeyPlain));
    //encrypted by password
    byte[] privKeyEnced = SymmEncoder.AES128EcbEnc(privKeyPlain, aseKey);
    byte[] pubKey = ecKey.getPubKey();
    byte[] walletData = new byte[pwd.length + pubKey.length + privKeyEnced.length + salt0.length
            + salt1.length];

    System.arraycopy(pwd, 0, walletData, 0, pwd.length);
    System.arraycopy(pubKey, 0, walletData, pwd.length, pubKey.length);
    System.arraycopy(privKeyEnced, 0, walletData, pwd.length + pubKey.length, privKeyEnced.length);
    System.arraycopy(salt0, 0, walletData, pwd.length + pubKey.length + privKeyEnced.length,
            salt0.length);
    System.arraycopy(salt1, 0, walletData,
            pwd.length + pubKey.length + privKeyEnced.length + salt0.length, salt1.length);

    FileUtil.saveData(FilePath, walletData);
  }


  public Transaction signTransaction(Transaction transaction) {
    if (this.ecKey == null || this.ecKey.getPrivKey() == null) {
      logger.warn("Warning: Can't sign,there is no private key !!");
      return null;
    }
    transaction = TransactionUtils.setTimestamp(transaction);
    return TransactionUtils.sign(transaction, this.ecKey);
  }

  public Transaction prepareTransaction(byte[] to, long amount) {
    byte[] owner = getAddress();

    Contract.TransferContract.Builder transferContractBuilder = Contract.TransferContract
            .newBuilder();
    ByteString bsTo = ByteString.copyFrom(to);
    ByteString bsOwner = ByteString.copyFrom(owner);
    transferContractBuilder.setToAddress(bsTo);
    transferContractBuilder.setOwnerAddress(bsOwner);
    transferContractBuilder.setAmount(amount);
    Contract.TransferContract tContract = transferContractBuilder.build();

    Transaction.Builder transactionBuilder = Transaction.newBuilder();
    Transaction.Contract.Builder contractBuilder = Transaction.Contract.newBuilder();

    try {
      Any anyTo = Any.pack(tContract);
      contractBuilder.setParameter(anyTo);
    } catch (Exception e) {
      return null;
    }

    contractBuilder.setType(Transaction.Contract.ContractType.TransferContract);
    transactionBuilder.getRawDataBuilder().addContract(contractBuilder);
    transactionBuilder.getRawDataBuilder().setType(Transaction.TransactionType.ContractType);

    Transaction transaction = transactionBuilder.build();
    if (transaction == null || transaction.getRawData().getContractCount() == 0){
      return null;
    }
    return transaction;
  }


  public static Contract.TransferContract createTransferContract(byte[] to, byte[] owner,
                                                                 long amount) {
    Contract.TransferContract.Builder builder = Contract.TransferContract.newBuilder();
    ByteString bsTo = ByteString.copyFrom(to);
    ByteString bsOwner = ByteString.copyFrom(owner);
    builder.setToAddress(bsTo);
    builder.setOwnerAddress(bsOwner);
    builder.setAmount(amount);

    return builder.build();
  }

  public static byte[] loadPassword() {
    byte[] buf = FileUtil.readData(FilePath);
    if (ArrayUtils.isEmpty(buf)) {
      return null;
    }
    if (buf.length != 145) {
      return null;
    }
    return Arrays.copyOfRange(buf, 0, 16);  //16
  }

  public static byte[] loadPubKey() {
    byte[] buf = FileUtil.readData(FilePath);
    if (ArrayUtils.isEmpty(buf)) {
      return null;
    }
    if (buf.length != 145) {
      return null;
    }
    return Arrays.copyOfRange(buf, 16, 81);  //65
  }

  private static byte[] loadPriKey() {
    byte[] buf = FileUtil.readData(FilePath);
    if (ArrayUtils.isEmpty(buf)) {
      return null;
    }
    if (buf.length != 145) {
      return null;
    }
    return Arrays.copyOfRange(buf, 81, 113);  //32
  }

  private static byte[] loadSalt0() {
    byte[] buf = FileUtil.readData(FilePath);
    if (ArrayUtils.isEmpty(buf)) {
      return null;
    }
    if (buf.length != 145) {
      return null;
    }
    return Arrays.copyOfRange(buf, 113, 129);  //16
  }

  private static byte[] loadSalt1() {
    byte[] buf = FileUtil.readData(FilePath);
    if (ArrayUtils.isEmpty(buf)) {
      return null;
    }
    if (buf.length != 145) {
      return null;
    }
    return Arrays.copyOfRange(buf, 129, 145);  //16
  }

  /**
   * Get a Wallet from storage
   */
  public static WalletClient GetWalletByStorageIgnorPrivKey() {
    try {
      byte[] pubKey = loadPubKey(); //04 PubKey
      ECKey eccKey = ECKey.fromPublicOnly(pubKey);
      return new WalletClient(eccKey);
    } catch (Exception ex) {
      ex.printStackTrace();
      return null;
    }
  }

  public static String getAddressByStorage() {
    try {
      byte[] pubKey = loadPubKey(); //04 PubKey
      return ByteArray.toHexString(ECKey.computeAddress(pubKey));
    } catch (Exception ex) {
      ex.printStackTrace();
      return null;
    }
  }

  public static byte[] getPassWord(String password, byte[] salt1) {
    if (!passwordValid(password)) {
      return null;
    }
    byte[] pwd;
    byte[] msg = new byte[password.length() + salt1.length];
    System.arraycopy(password.getBytes(), 0, msg, 0, password.length());
    System.arraycopy(salt1, 0, msg, password.length(), salt1.length);
    pwd = Hash.sha256(msg);
    pwd = Hash.sha256(pwd);
    pwd = Arrays.copyOfRange(pwd, 0, 16);
    return pwd;
  }

  public static byte[] getEncKey(String password, byte[] salt0) {
    if (!passwordValid(password)) {
      return null;
    }
    byte[] encKey;
    byte[] msg = new byte[password.length() + salt0.length];
    System.arraycopy(password.getBytes(), 0, msg, 0, password.length());
    System.arraycopy(salt0, 0, msg, password.length(), salt0.length);
    encKey = Hash.sha256(msg);
    encKey = Arrays.copyOfRange(encKey, 0, 16);
    return encKey;
  }

  public static boolean checkPassWord(String password) {
    byte[] salt1 = loadSalt1();
    if (ArrayUtils.isEmpty(salt1)) {
      return false;
    }
    byte[] pwd = getPassWord(password, salt1);
    byte[] pwdStored = loadPassword();

    return Arrays.equals(pwd, pwdStored);
  }

  public static boolean passwordValid(String password) {
    if (StringUtils.isEmpty(password)) {
      logger.warn("Warning: Password is empty !!");
      return false;
    }
    if (password.length() < 6) {
      logger.warn("Warning: Password is too short !!");
      return false;
    }
    //Other rule;
    return true;
  }

  public static boolean addressValid(byte[] address) {
    if (address == null || address.length == 0) {
      logger.warn("Warning: Address is empty !!");
      return false;
    }
    if (address.length != CommonConstant.ADDRESS_SIZE) {
      logger.warn("Warning: Address length need " + CommonConstant.ADDRESS_SIZE + " but " + address.length
              + " !!");
      return false;
    }
    byte preFixbyte = address[0];
    if (preFixbyte != CommonConstant.ADD_PRE_FIX_BYTE) {
      logger.warn("Warning: Address need prefix with " + CommonConstant.ADD_PRE_FIX_BYTE + " but "
              + preFixbyte + " !!");
      return false;
    }
    //Other rule;
    return true;
  }

  public static String encode58Check(byte[] input) {
    byte[] hash0 = Hash.sha256(input);
    byte[] hash1 = Hash.sha256(hash0);
    byte[] inputCheck = new byte[input.length + 4];
    System.arraycopy(input, 0, inputCheck, 0, input.length);
    System.arraycopy(hash1, 0, inputCheck, input.length, 4);
    return Base58.encode(inputCheck);
  }

  private static byte[] decode58Check(String input) {
    byte[] decodeCheck = Base58.decode(input);
    if (decodeCheck.length <= 4) {
      return null;
    }
    byte[] decodeData = new byte[decodeCheck.length - 4];
    System.arraycopy(decodeCheck, 0, decodeData, 0, decodeData.length);
    byte[] hash0 = Hash.sha256(decodeData);
    byte[] hash1 = Hash.sha256(hash0);
    if (hash1[0] == decodeCheck[decodeData.length] &&
            hash1[1] == decodeCheck[decodeData.length + 1] &&
            hash1[2] == decodeCheck[decodeData.length + 2] &&
            hash1[3] == decodeCheck[decodeData.length + 3]) {
      return decodeData;
    }
    return null;
  }

  public static byte[] decodeFromBase58Check(String addressBase58) {
    if (StringUtils.isEmpty(addressBase58)) {
      logger.warn("Warning: Address is empty !!");
      return null;
    }
    if (addressBase58.length() != CommonConstant.BASE58CHECK_ADDRESS_SIZE) {
      logger.warn("Warning: Base58 address length need " + CommonConstant.BASE58CHECK_ADDRESS_SIZE
              + " but " + addressBase58.length() + " !!");
      return null;
    }
    byte[] address = decode58Check(addressBase58);
    if (!addressValid(address)) {
      return null;
    }
    return address;
  }

  public static boolean priKeyValid(String priKey) {
    if (StringUtils.isEmpty(priKey)) {
      logger.warn("Warning: PrivateKey is empty !!");
      return false;
    }
    if (priKey.length() != 64) {
      logger.warn("Warning: PrivateKey length need 64 but " + priKey.length() + " !!");
      return false;
    }
    //Other rule;
    return true;
  }


}