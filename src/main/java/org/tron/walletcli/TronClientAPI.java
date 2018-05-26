package org.tron.walletcli;

import org.json.simple.JSONObject;
import org.springframework.web.bind.annotation.*;
import org.tron.common.utils.FileUtil;

import java.io.*;
import java.security.KeyStore;


@RestController
@RequestMapping("/api")
public class TronClientAPI {
    private TronClient tronClient = new TronClient();
    private static Encryption encryption;

    {
        try{
            InputStream inputStream = getClass().getResourceAsStream("/tronks.ks");
            String data = FileUtil.readFromInputStream(inputStream);
            System.out.println("STRING IS: " + data);
            encryption = new Encryption(data.trim());
        }catch (Exception e){
            //e.printStackTrace();
            System.out.println("INITEXCEPTION: " + e.getMessage());
        }

    }


    @RequestMapping(value="/registerWallet", method=RequestMethod.POST)
    public String registerWallet(@RequestParam("password") String password,
                                     @RequestParam("accountName") String accountName){

        password = encryption.decryptText(password);
        accountName = encryption.decryptText(accountName);

        JSONObject json_obj = tronClient.registerWallet(password, accountName);
        tronClient.login(password);
        System.out.println("JSON: " + json_obj);
        System.out.println("ENC JSON: " + encryption.encryptObject(json_obj));
        return encryption.encryptObject(json_obj);
    }

    @RequestMapping(value="/createPaperWallet", method=RequestMethod.POST)
    public String createPaperWallet(){
        JSONObject json_obj = tronClient.createPaperWallet();
        return encryption.encryptObject(json_obj);
    }


    @RequestMapping(value="/importWallet", method=RequestMethod.POST)
    public String importWallet(@RequestParam("password") String password,
                                    @RequestParam("privKey") String privKey){

        password = encryption.decryptText(password);
        privKey = encryption.decryptText(privKey);

        JSONObject json_obj = tronClient.importWallet(password, privKey);
        tronClient.login(password);
        return encryption.encryptObject(json_obj);
    }


    @RequestMapping(value="/login", method=RequestMethod.POST)
    public String login(@RequestParam("password") String password){
        password = encryption.decryptText(password);
        return encryption.encryptObject(tronClient.login(password));
    }

    @RequestMapping(value="/logout", method=RequestMethod.POST)
    public String logout(){
        return encryption.encryptObject(tronClient.logout());
    }

    @RequestMapping(value="/backupWallet/{password}", method=RequestMethod.GET)
    public String backupWallet(@PathVariable("password") String password){
        password = encryption.decryptText(password);
        return encryption.encryptObject(tronClient.backupWallet(password));
    }


    @RequestMapping(value="/prepareTx", method=RequestMethod.POST)
    public String prepareTransaction(@RequestParam("toAddress") String toAddress,
                                         @RequestParam("amount") String amount){
        toAddress = encryption.decryptText(toAddress);
        amount = encryption.decryptText(amount);

        Double dbl_amount = Double.parseDouble(amount.trim());
        return encryption.encryptObject(tronClient.prepareTransaction(toAddress, dbl_amount.longValue()));
    }

    @RequestMapping(value="/signTxInfo/{hextx}", method=RequestMethod.GET)
    public String getSignTxInfo(@PathVariable("hextx") String hextx){
        hextx = encryption.decryptText(hextx);
        return encryption.encryptObject(tronClient.getSignTxInfo(hextx));
    }

    @RequestMapping(value="/signTx", method=RequestMethod.POST)
    public String signTransaction(@RequestParam("hextx") String hextx){
        hextx = encryption.decryptText(hextx);
        return encryption.encryptObject(tronClient.signTransaction(hextx));
    }

    @RequestMapping(value="/txs/{pubAddress}", method=RequestMethod.GET)
    public String getTransactions(@PathVariable("pubAddress") String pubAddress){
        pubAddress = encryption.decryptText(pubAddress);
        return encryption.encryptObject(tronClient.getTransactions(pubAddress));
    }

    @RequestMapping(value="/validatePass", method=RequestMethod.POST)
    public String validatePasscode(@RequestParam("password") String password,
                                   @RequestParam("store") String store){
        password = encryption.decryptText(password);
        System.out.println("BOOL: " + encryption.decryptText(store));
        Boolean tostore = Boolean.parseBoolean(encryption.decryptText(store));
        System.out.println("ACTU?AL BOOL: " + tostore);
        return encryption.encryptObject(tronClient.validatePasscodeImport(password,tostore));
    }

    @RequestMapping(value="/pdirty", method=RequestMethod.GET)
    public String getPDirty(){
        return encryption.encryptObject(tronClient.isPDirty());
    }
}
