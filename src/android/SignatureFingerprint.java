package com.fontesoft.cordova;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.PackageManager;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.lang.StringBuilder;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import android.os.Build;

public class SignatureFingerprint extends CordovaPlugin {

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
	    //////////////////////////////////
	    //////////////////////////////////
	    
	    cordova.getThreadPool().execute(new Runnable() {
	    public void run() {
	    
	    //////////////////////////////////
	    //////////////////////////////////  
		
        if (action.equals("getPackageName")) {
          callbackContext.success(cordova.getActivity().getPackageName());
          //return true;
        }
        if (action.equals("getSignature")) {
            String packageName = cordova.getActivity().getPackageName();
            PackageManager pm = cordova.getActivity().getPackageManager();
            int flags = PackageManager.GET_SIGNATURES;
            PackageInfo packageInfo = null;
                       
            /*
            try {
                packageInfo = pm.getPackageInfo(packageName, flags);
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
            */
            //nabil in case the packageinfi is null then check on API level 28 and above and use PackageManager.GET_SIGNING_CERTIFICATES because PackageManager.GET_SIGNATURES is deprecated
            try {
                packageInfo = pm.getPackageInfo(packageName, flags);
                if((packageInfo == null || packageInfo.signatures == null || packageInfo.signatures.length == 0
                    || packageInfo.signatures[0] == null) && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
                        {
                            flags = PackageManager.GET_SIGNING_CERTIFICATES;
                            packageInfo = pm.getPackageInfo(packageName, flags);
                        }
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
            
            
            Signature[] signatures = packageInfo.signatures;
            byte[] cert = signatures[0].toByteArray();
            InputStream input = new ByteArrayInputStream(cert);
            CertificateFactory cf = null;
            try {
                cf = CertificateFactory.getInstance("X509");
            } catch (CertificateException e) {
                e.printStackTrace();
            }
            X509Certificate c = null;
            try {
                c = (X509Certificate) cf.generateCertificate(input);
            } catch (CertificateException e) {
                e.printStackTrace();
            }
            String hexString = null;
            try {
                //nabil use SHA-256 instead of SHA1
                MessageDigest md = MessageDigest.getInstance("SHA-256");
        	    byte[] publicKey = md.digest(c.getEncoded());
                //MessageDigest md = MessageDigest.getInstance("SHA1");
                //byte[] publicKey = md.digest(c.getEncoded());
                hexString = byte2HexFormatted(publicKey);
            } catch (NoSuchAlgorithmException e1) {
                e1.printStackTrace();
            } catch (CertificateEncodingException e) {
                e.printStackTrace();
            }
            callbackContext.success(hexString);
            //return true;
        }
        
        //////////////////////////////////
        //////////////////////////////////
        }
        });
        //////////////////////////////////
        //////////////////////////////////
	    
        return true;
    }

    public static String byte2HexFormatted(byte[] arr) {
        StringBuilder str = new StringBuilder(arr.length * 2);
        for (int i = 0; i < arr.length; i++) {
            String h = Integer.toHexString(arr[i]);
            int l = h.length();
            if (l == 1) h = "0" + h;
            if (l > 2) h = h.substring(l - 2, l);
            str.append(h.toUpperCase());
            if (i < (arr.length - 1)) str.append(':');
        }
        return str.toString();
    }
}
