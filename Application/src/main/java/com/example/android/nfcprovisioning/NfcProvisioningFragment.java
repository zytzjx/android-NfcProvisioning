/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.android.nfcprovisioning;

import android.app.Activity;
import android.app.PendingIntent;
import android.app.ProgressDialog;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.net.Uri;
import android.nfc.FormatException;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.NfcEvent;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.Ndef;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.loader.app.LoaderManager;
import androidx.loader.content.Loader;

import android.os.StrictMode;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.Switch;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

/**
 * Provides UI and logic for NFC provisioning.
 * <p>
 * This fragment creates an intent, which sends parameters to a second device via an Nfc bump. If
 * the second device is factory reset, this will start provisioning the second device to set it up
 * as an owned device.
 * </p>
 */
public class NfcProvisioningFragment extends Fragment implements
        NfcAdapter.CreateNdefMessageCallback,
        TextWatcherWrapper.OnTextChangedListener,
        LoaderManager.LoaderCallbacks<Map<String, String>> {

    private static final int LOADER_PROVISIONING_VALUES = 1;

    // View references
    private EditText mEditPackageName;
    private EditText mEditClassName;
    private EditText mEditLocale;
    private EditText mEditTimezone;
    private EditText mEditWifiSsid;
    private EditText mEditWifiSecurityType;
    private EditText mEditWifiPassword;
    private EditText mEditCompany;
    private EditText mEditSite;
    private EditText mEditNfcId;
    private EditText mEditApkName;
    private Switch mSwitch;
    private Switch  mUseOnly;
    private CheckBox mchkHide;

    // Values to be set via NFC bump
    private Map<String, String> mProvisioningValues;
    private volatile  String mCompany, mSite, mNFCId;


    private ProgressDialog pDialog;

    // File url to download
    private static String file_url = "http://10.1.1.105/vvv.apk";


    Tag myTag;
    NfcAdapter adapter;
    boolean writeMode=true;
    Boolean mBWrite = true;
    Boolean mbHidden = false;
    boolean muserdownloadurl=false;


    public class TrustAllCertsManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            // Do nothing -> accept any certificates
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            // Do nothing -> accept any certificates
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    public class VerifyEverythingHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }


    /**
     * Background Async Task to download file
     * */
    class DownloadFileFromURL extends AsyncTask<String, String, String> {

        /**
         * Before starting background thread Show Progress Bar Dialog
         * */
        @Override
        protected void onPreExecute() {
            super.onPreExecute();
            pDialog = new ProgressDialog(getActivity());
            pDialog.setMessage("Downloading file. Please wait...");
            pDialog.setIndeterminate(false);
            pDialog.setMax(100);
            pDialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
            pDialog.setCancelable(true);
            pDialog.show();

//            TrustManager[] trustManager = new TrustManager[] {new TrustAllCertsManager()};
//            SSLContext sslContext = null;
//            try {
//                sslContext = SSLContext.getInstance("SSL");
//                sslContext.init(null, trustManager, new java.security.SecureRandom());
//            } catch (NoSuchAlgorithmException e) {
//                // do nothing
//            }catch (KeyManagementException e) {
//                // do nothing
//            }
//            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        }


        String downloadPost(String sUrl1){
            HttpURLConnection httpsURLConnection = null;

            int count;
            try {
                String sUrl = URLDecoder.decode(sUrl1, "UTF-8");
                Uri uri = Uri.parse(sUrl);
                List<String> pps = uri.getPathSegments();
                Uri.Builder builder = new Uri.Builder();
                builder.scheme(uri.getScheme())
                        .authority(uri.getHost())
                        .appendPath("c").
                        appendPath(pps.get(pps.size()-1));
                URL url = new URL(builder.toString()+"/");
                Log.d("FDIAL", url.toString());
                //URL url = new URL("https://httpbin.org/post");
                //URL url = new URL("https://fsmc.futuredial.com/c/1.apk/");
                if(uri.getScheme().equalsIgnoreCase("https")) {
                    httpsURLConnection = (HttpsURLConnection) url.openConnection();
                }else {
                    httpsURLConnection = (HttpURLConnection) url.openConnection();
                }
                httpsURLConnection.setRequestMethod("POST");
                //httpsURLConnection.setRequestMethod("GET");

                httpsURLConnection.setConnectTimeout(5000);
                httpsURLConnection.setDoInput(true);
                httpsURLConnection.setDoOutput(true);
                httpsURLConnection.setUseCaches(false);

                StringBuilder result = new StringBuilder();
                result.append(URLEncoder.encode("username", "UTF-8")).append("=").append(URLEncoder.encode("fsmcwu", "UTF-8")).append("&");
                result.append(URLEncoder.encode("password", "UTF-8")).append("=").append(URLEncoder.encode("w78u", "UTF-8"));
                httpsURLConnection.setFixedLengthStreamingMode(result.toString().getBytes().length);

                httpsURLConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                httpsURLConnection.setRequestProperty("Accept", "*/*");
                httpsURLConnection.setRequestProperty("User-Agent", "curl/7.55.1");
                if(httpsURLConnection.getRequestMethod()=="GET") {
                    httpsURLConnection.connect();
                }

                OutputStream out = httpsURLConnection.getOutputStream();
                out.write(result.toString().getBytes("UTF-8"));
                //流用完记得关
                out.flush();
                out.close();

                int responseCode = httpsURLConnection.getResponseCode();
                Log.d("NFCCHECK","\nSending 'POST' request to URL : " + url);
                //System.out.println("Post parameters : " + result.toString());
                Log.d("NFCCHECK","Response Code : " + responseCode);

                // progress bar
                int lenghtOfFile = httpsURLConnection.getContentLength();

                InputStream input = httpsURLConnection.getInputStream();
                ByteArrayOutputStream output1 = new ByteArrayOutputStream();
                byte data[] = new byte[1024];

                long total = 0;

                while ((count = input.read(data)) != -1) {
                    //System.out.println(new String(data,0, count, StandardCharsets.UTF_8));
                    total += count;
                    // publishing the progress....
                    // After this onProgressUpdate will be called
                    publishProgress("" + (int) ((total * 100) / lenghtOfFile));

                    // writing data to file
                    output1.write(data, 0, count);
                }

                // flushing output
                output1.flush();

                MessageDigest digest = null;
                MessageDigest digest256 = null;
                try {
                    digest = MessageDigest.getInstance("SHA-1");
                    digest256 = MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }

                byte[] apkBytes = new byte[0];
                apkBytes = output1.toByteArray();

                digest.update(apkBytes);
                //digest256.update(apkBytes);
                digest256.reset();

                String sCheckSum = Base64.encodeToString(digest.digest(), Base64.URL_SAFE).replace("=","");
                String sCheckSum256 = Base64.encodeToString(digest256.digest(apkBytes), Base64.URL_SAFE).replace("=","");
                Log.d("NFCCHECK", sCheckSum);
                Log.d("NFCCHECK", sCheckSum256);

                SetCheckSum(getActivity(), sCheckSum, sCheckSum256);

                // closing streams
                output1.close();
                input.close();

            } catch (Exception e) {
                Log.e("Error: ", e.getMessage());
                e.printStackTrace();
            }

            return null;

        }
        String downloadGet(String sUrl1){
            HttpURLConnection httpsURLConnection = null;

            int count;
            try {
                String sUrl = URLDecoder.decode(sUrl1, "UTF-8");

                URL url = new URL(sUrl);
                Log.d("FDIAL", url.toString());
                //URL url = new URL("https://httpbin.org/post");
                //URL url = new URL("https://fsmc.futuredial.com/c/1.apk/");
                if(sUrl.startsWith("https")) {
                    httpsURLConnection = (HttpsURLConnection) url.openConnection();
                }else {
                    httpsURLConnection = (HttpURLConnection) url.openConnection();
                }
                httpsURLConnection.setRequestMethod("GET");
                httpsURLConnection.setConnectTimeout(5000);
//                httpsURLConnection.setDoInput(true);  //get must remove
//                httpsURLConnection.setDoOutput(true);//get must remove
                httpsURLConnection.setUseCaches(false);

                httpsURLConnection.setRequestProperty("Accept", "*/*");
                httpsURLConnection.setRequestProperty("User-Agent", "curl/7.55.1");
                httpsURLConnection.connect();

                int responseCode = httpsURLConnection.getResponseCode();
                Log.d("NFCCHECK","\nSending 'POST' request to URL : " + url);
                //System.out.println("Post parameters : " + result.toString());
                Log.d("NFCCHECK","Response Code : " + responseCode);

                // progress bar
                int lenghtOfFile = httpsURLConnection.getContentLength();

                InputStream input = httpsURLConnection.getInputStream();
                ByteArrayOutputStream output1 = new ByteArrayOutputStream();
                byte data[] = new byte[1024];

                long total = 0;

                while ((count = input.read(data)) != -1) {
                    //System.out.println(new String(data,0, count, StandardCharsets.UTF_8));
                    total += count;
                    // publishing the progress....
                    // After this onProgressUpdate will be called
                    publishProgress("" + (int) ((total * 100) / lenghtOfFile));

                    // writing data to file
                    output1.write(data, 0, count);
                }

                // flushing output
                output1.flush();

                MessageDigest digest = null;
                MessageDigest digest256 = null;
                try {
                    digest = MessageDigest.getInstance("SHA-1");
                    digest256 = MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }

                byte[] apkBytes = new byte[0];
                apkBytes = output1.toByteArray();

                digest.update(apkBytes);
                //digest256.update(apkBytes);
                digest256.reset();

                String sCheckSum = Base64.encodeToString(digest.digest(), Base64.URL_SAFE);//.replace("=","");
                String sCheckSum256 = Base64.encodeToString(digest256.digest(apkBytes), Base64.URL_SAFE);//.replace("=","");
                Log.d("NFCCHECK", sCheckSum);
                Log.d("NFCCHECK", sCheckSum256);

                SetCheckSum(getActivity(), sCheckSum, sCheckSum256);

                // closing streams
                output1.close();
                input.close();

            } catch (Exception e) {
                Log.e("Error: ", e.getMessage());
                e.printStackTrace();
            }

            return null;

        }
        /**
         * Downloading file in background thread
         * */
        @Override
        protected String doInBackground(String... f_url) {
            if (muserdownloadurl){
                return downloadGet(f_url[0]);
            }else{
                return  downloadPost(f_url[0]);
            }
        }

        /**
         * Updating progress bar
         * */
        protected void onProgressUpdate(String... progress) {
            // setting progress percentage
            pDialog.setProgress(Integer.parseInt(progress[0]));
        }

        /**
         * After completing background task Dismiss the progress dialog
         * **/
        @Override
        protected void onPostExecute(String file_url) {
            // dismiss the dialog after the file was downloaded
            if (pDialog != null)
            {
                pDialog.dismiss();
            }
        }

    }

    public static void SetConfig(Context context, String key, String value){
        SharedPreferences settings = context.getSharedPreferences("Config", 0);
        SharedPreferences.Editor editor = settings.edit();
        editor.putString(key, value);
        editor.commit();

    }

    public  static String GetConfig(Context context, String key){
        SharedPreferences settings = context.getSharedPreferences("Config", 0);
        String bDone = settings.getString(key, "");
        android.util.Log.d("FDIAL", "GetFDDone: "+bDone);
        return  bDone;
    }

    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);
        return inflater.inflate(R.layout.fragment_nfc_provisioning, container, false);
    }

    @Override
    public void onViewCreated(View view, @Nullable Bundle savedInstanceState) {
        // Retrieve view references
        mEditPackageName = (EditText) view.findViewById(R.id.package_name);
        mEditClassName = (EditText) view.findViewById(R.id.class_name);
        mEditLocale = (EditText) view.findViewById(R.id.locale);
        mEditTimezone = (EditText) view.findViewById(R.id.timezone);
        mEditWifiSsid = (EditText) view.findViewById(R.id.wifi_ssid);
        mEditWifiSecurityType = (EditText) view.findViewById(R.id.wifi_security_type);
        mEditWifiPassword = (EditText) view.findViewById(R.id.wifi_password);
        mEditCompany = (EditText) view.findViewById(R.id.company);
        mEditSite = (EditText) view.findViewById(R.id.site);
        mEditNfcId = (EditText) view.findViewById(R.id.nfcid);
        mEditApkName = (EditText) view.findViewById(R.id.apkname);
        mSwitch = (Switch) view.findViewById(R.id.switch1);
        mUseOnly = view.findViewById(R.id.switch2);
        mSwitch.setChecked(true);
        mUseOnly.setChecked(false);
        mSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                mBWrite = isChecked;
            }
        });
        mUseOnly.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                muserdownloadurl = isChecked;
            }
        });

        mchkHide = (CheckBox)view.findViewById(R.id.wifi_ssid_hide);
        mchkHide.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                mbHidden = isChecked;
                SetConfig(getActivity(),"hidden", mbHidden.toString());
            }
        });

        // Bind event handlers
        mEditPackageName.addTextChangedListener(new TextWatcherWrapper(R.id.package_name, this));
        mEditClassName.addTextChangedListener(new TextWatcherWrapper(R.id.class_name, this));
        mEditLocale.addTextChangedListener(new TextWatcherWrapper(R.id.locale, this));
        mEditTimezone.addTextChangedListener(new TextWatcherWrapper(R.id.timezone, this));
        mEditWifiSsid.addTextChangedListener(new TextWatcherWrapper(R.id.wifi_ssid, this));
        mEditWifiSecurityType.addTextChangedListener(
                new TextWatcherWrapper(R.id.wifi_security_type, this));
        mEditWifiPassword.addTextChangedListener(new TextWatcherWrapper(R.id.wifi_password, this));
        mEditCompany.addTextChangedListener(new TextWatcherWrapper(R.id.company, this));
        mEditSite.addTextChangedListener(new TextWatcherWrapper(R.id.site, this));
        mEditNfcId.addTextChangedListener(new TextWatcherWrapper(R.id.nfcid, this));
        mEditNfcId.setEnabled(false);
        mEditApkName.addTextChangedListener(new TextWatcherWrapper(R.id.apkname, this));

        Button button = (Button) view.findViewById(R.id.download);
        button.setOnClickListener(new View.OnClickListener()
        {
            @Override
            public void onClick(View v)
            {
//                Uri.Builder builder = new Uri.Builder();
//                builder.scheme("https")
//                        .authority("fsmc.futuredial.com")
//                        .appendPath("c").
//                        appendPath(GetConfig(getActivity(),"apkname"));
                Uri uri = Uri.parse(GetConfig(getActivity(),"apkname"));
                Log.d("FDIAL",uri.getPath());
                new DownloadFileFromURL().execute(uri.toString());
            }
        });

        // Prior to API 23, the class name is not needed
        //mEditClassName.setVisibility(Build.VERSION.SDK_INT >= 23 ? View.VISIBLE : View.GONE);
    }

    @Override
    public void onStart() {
        super.onStart();
        Activity activity = getActivity();
        //builder.scheme("https").authority("fsmc.futuredial.com").appendPath("files").appendPath("download_files");
        //TODO:https://fsmc.futuredial.com/files/download_files/1.apk
        //builder.appendPath("vvv.apk");
        //builder.appendQueryParameter("id","serialnumber");

        adapter = NfcAdapter.getDefaultAdapter(activity);
        if (adapter != null) {
            adapter.setNdefPushMessageCallback(this, activity);
        }
        //WriteModeOn();
        getLoaderManager().initLoader(LOADER_PROVISIONING_VALUES, null, this);
    }

    @Override
    public void onResume() {
        super.onResume();
        if(mBWrite)
            WriteModeOn();
    }

    @Override
    public void onPause() {
        super.onPause();
        if(mBWrite)
            WriteModeOff();
    }

    public static int copy(InputStream input, OutputStream output) throws IOException {
        long count = copyLarge(input, output);
        if (count > Integer.MAX_VALUE) {
            return -1;
        }
        return (int) count;
    }

    private void gatherAdminExtras(String scompany, String sSite, String nfcid) {
       if(mProvisioningValues==null) return ;
        try{
            if (TextUtils.isEmpty(nfcid)){

            }

            String s=String.format("sid=%s\ncid=%s\nnfid=%s\n", sSite, scompany, nfcid);
            mProvisioningValues.put(
                    DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, s);
        } catch (Exception e) {
        }
    }

    public static void SetCheckSum(Context context, String sSHA1, String sSHA256){
        SharedPreferences settings = context.getSharedPreferences("CheckSum", 0);
        SharedPreferences.Editor editor = settings.edit();
        editor.putString("sha1", sSHA1);
        editor.putString("sha256", sSHA256);
        editor.commit();

    }

    public  static String GetCheckSum(Context context, String skey){
        SharedPreferences settings = context.getSharedPreferences("CheckSum", 0);
        String sChecksum = settings.getString(skey, "");
        android.util.Log.d("FDIAL", "GetCheckSum: "+sChecksum);
        return  sChecksum;
    }

    private static final int DEFAULT_BUFFER_SIZE = 1024 * 4;

    /**
     * Convert bytes to hex string.
     *
     * @param b the bytes array to convert.
     * @param size the size of the array to consider.
     * @return the hex string.
     */
    public static String getHexString( byte[] b, int size ) {
        if (size < 1) {
            size = b.length;
        }
        StringBuilder sb = new StringBuilder();
        for( int i = 0; i < size; i++ ) {
            if (i >= 0)
                sb.append(Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString().toUpperCase();
    }

    public  void processNFC(Intent intent)
    {
        Log.d("TAGS", "processNFC++");
        Log.d("TAGS", "processNFC: "+intent.getAction());
        if (NfcAdapter.ACTION_TAG_DISCOVERED.equals(intent.getAction())){
            myTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            byte[] idBytes = null;
            if (myTag != null) {
                idBytes = myTag.getId();
            } else {
                idBytes = intent.getByteArrayExtra(NfcAdapter.EXTRA_ID);
            }
            //mNFCId = getHexString(idBytes, -1);
            //mEditNfcId.setText(mNFCId);

            try {
                write(myTag);
            } catch (IOException e) {
                e.printStackTrace();
            } catch (FormatException e) {
                e.printStackTrace();
            }

        }
    }

    /******************************************************************************
     **********************************Enable Write********************************
     ******************************************************************************/
    private void WriteModeOn(){
        writeMode = true;
        PendingIntent pendingIntent = PendingIntent.getActivity(getActivity(), 0, new Intent(getActivity(), getActivity().getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        IntentFilter tagDetected = new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED);
        tagDetected.addCategory(Intent.CATEGORY_DEFAULT);
        IntentFilter writeTagFilters[] = new IntentFilter[] { tagDetected };
        adapter.enableForegroundDispatch(getActivity(), pendingIntent, writeTagFilters, null);
    }
    /******************************************************************************
     **********************************Disable Write*******************************
     ******************************************************************************/
    private void WriteModeOff(){
        writeMode = false;
        adapter.disableForegroundDispatch(getActivity());
    }

    public static long copyLarge(InputStream input, OutputStream output)
            throws IOException {
        byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
        long count = 0;
        int n = 0;
        while (-1 != (n = input.read(buffer))) {
            output.write(buffer, 0, n);
            count += n;
        }
        return count;
    }

    private class AsyncConnectWrite extends AsyncTask<Object, Void, String> {
        @Override
        protected String doInBackground(Object... params) {
            String result = "";
            final String className = "TAGS";

            NdefMessage message = (NdefMessage) params[0];
            Ndef ndef = (Ndef) params[1];
            try {
                if (ndef != null) {
                    // Try to connect to the tag
                    ndef.connect();
                    if (ndef.isConnected()) {
                        // Write the message
                        ndef.writeNdefMessage(message);
                    }
                }
            } catch (FormatException e) {
                Log.e(className, "FormatException while writing…", e);
                result = "FormatException while writing";
            } catch (TagLostException e) {
                Log.e(className, "TagLostException while writing…", e);
                result = "TagLostException while writing";
            } catch (IOException e) {
                Log.e(className, "IOException while writing…", e);
                result = "IOException while writing";
            }finally {
                try {
                    if (ndef != null) {
                        ndef.close();
                        if(TextUtils.isEmpty(result)) {
                            result = "Message written!";
                        }
                    }
                } catch (IOException e) {
                    Log.e(className, "IOException while closing…", e);
                    result = "IOException while closing";
                }
            }
            return result;
        }
        @Override
        protected void onPostExecute(String result) {
            if (!result.isEmpty()) {
                Toast.makeText(getActivity(), result, Toast.LENGTH_LONG).show();
            }
        }
    }

    /******************************************************************************
     **********************************Write to NFC Tag****************************
     ******************************************************************************/
    private void write(Tag tag) throws IOException, FormatException {
        // Get an instance of Ndef for the tag.
        if (TextUtils.isEmpty(mCompany) || TextUtils.isEmpty(mSite) || TextUtils.isEmpty(mNFCId)){
            Toast.makeText(getActivity(), "CompanyID, SiteID, NFC ID can not be empty", Toast.LENGTH_LONG).show();
            return ;
        }

        Ndef ndef = Ndef.get(tag);
        NdefMessage ndfmsg = createRecord();
        new AsyncConnectWrite().execute(ndfmsg, ndef);
    }
    private NdefMessage createRecord() throws UnsupportedEncodingException {
        Log.d("TAGS", "createNdefMessage++");
        if (mProvisioningValues == null) {
            return null;
        }

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        Properties properties = new Properties();
        // Store all the values into the Properties object
        for (Map.Entry<String, String> e : mProvisioningValues.entrySet()) {
            if (!TextUtils.isEmpty(e.getValue())) {
                String value;
                if (e.getKey().equals(DevicePolicyManager.EXTRA_PROVISIONING_WIFI_SSID)) {
                    // Make sure to surround SSID with double quotes
                    value = e.getValue();
                    if (!value.startsWith("\"") || !value.endsWith("\"")) {
                        value = "\"" + value + "\"";
                    }
                } else //noinspection deprecation
                    if (e.getKey().equals(
                            DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_NAME)
                            && Build.VERSION.SDK_INT >= 23) {
                        continue;
                    } else {
                        value = e.getValue();
                    }
                properties.put(e.getKey(), value);
            }
        }
        // Make sure to put local time in the properties. This is necessary on some devices to
        // reliably download the device owner APK from an HTTPS connection.
        if (!properties.contains(DevicePolicyManager.EXTRA_PROVISIONING_LOCAL_TIME)) {
            //properties.put(DevicePolicyManager.EXTRA_PROVISIONING_LOCAL_TIME,
                    //String.valueOf(System.currentTimeMillis()));
        }

        if(mbHidden){
            properties.setProperty(DevicePolicyManager.EXTRA_PROVISIONING_WIFI_HIDDEN, "true");
        }

        try {
            //properties.setProperty(DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_NAME, getResources().getString(R.string.packagename));//
            //https://bit.ly/2M9bFcC
            //"https://github.com/zytzjx/testfile/raw/master/Application-debug.apk"
            //http://58.213.22.146/dl/Application-debug.apk
            //http://10.1.1.105/devowner.apk
            //todo: file_url = builder.toString();
           // Uri.Builder builder = new Uri.Builder();
            //builder.scheme("https").authority("fsmc.futuredial.com").appendPath("a").appendPath(mNFCId).appendPath(GetConfig(getActivity(),"apkname"));
            Uri uri = Uri.parse(GetConfig(getActivity(),"apkname"));

            properties.setProperty(DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION, uri.toString()+"/");
//            String sCheckSum = Base64.encodeToString(digest.digest(), Base64.URL_SAFE).replace("=","");
//            String sCheckSum256 = Base64.encodeToString(digest256.digest(), Base64.URL_SAFE).replace("=","");
//            Log.d("NFCCHECK", sCheckSum);
//            Log.d("NFCCHECK", sCheckSum256);
            String sCheckSum = GetCheckSum(getActivity(),"sha256");
            Log.d("NFCCHECK", sCheckSum);
            properties.setProperty(DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM, sCheckSum);


            properties.setProperty(DevicePolicyManager.EXTRA_PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED, "true");
            properties.setProperty(DevicePolicyManager.EXTRA_PROVISIONING_SKIP_ENCRYPTION, "true");

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        //https://github.com/zytzjx/testfile/raw/master/Application-debug.apk
        try {
            properties.store(stream, null); //getString(R.string.nfc_comment)
            String str = new String(stream.toByteArray(), StandardCharsets.UTF_8);
            int nPos = str.indexOf(System.lineSeparator());
            if(nPos>0)
                str = str.substring(nPos+System.lineSeparator().length());
            NdefRecord record = NdefRecord.createMime(
                    DevicePolicyManager.MIME_TYPE_PROVISIONING_NFC, str.getBytes(Charset.forName("UTF-8")));//stream.toByteArray());
            return new NdefMessage(new NdefRecord[]{record});
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;

    }

    @Override
    public NdefMessage createNdefMessage(NfcEvent event) {
        Log.d("TAGS", "createNdefMessage++");
        if (mProvisioningValues == null) {
            return null;
        }

//        MessageDigest digest = null;
//        MessageDigest digest256 = null;
//        try {
//            digest = MessageDigest.getInstance("SHA-1");
//            digest256 = MessageDigest.getInstance("SHA-256");
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//
//        byte[] apkBytes = new byte[0];
//        try {
//            ByteArrayOutputStream output = new ByteArrayOutputStream();
//            copy(getActivity().getAssets().open("Application-debug.apk"), output);
//            apkBytes = output.toByteArray();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//
//        digest.update(apkBytes);
//        digest256.update(apkBytes);


        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        Properties properties = new Properties();
        // Store all the values into the Properties object
        for (Map.Entry<String, String> e : mProvisioningValues.entrySet()) {
            if (!TextUtils.isEmpty(e.getValue())) {
                String value;
                if (e.getKey().equals(DevicePolicyManager.EXTRA_PROVISIONING_WIFI_SSID)) {
                    // Make sure to surround SSID with double quotes
                    value = e.getValue();
                    if (!value.startsWith("\"") || !value.endsWith("\"")) {
                        value = "\"" + value + "\"";
                    }
                } else //noinspection deprecation
                    if (e.getKey().equals(
                            DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_NAME)
                            && Build.VERSION.SDK_INT >= 23) {
                        continue;
                    } else {
                        value = e.getValue();
                    }
                properties.put(e.getKey(), value);
            }
        }
        // Make sure to put local time in the properties. This is necessary on some devices to
        // reliably download the device owner APK from an HTTPS connection.
        if (!properties.contains(DevicePolicyManager.EXTRA_PROVISIONING_LOCAL_TIME)) {
            //properties.put(DevicePolicyManager.EXTRA_PROVISIONING_LOCAL_TIME,
            //        String.valueOf(System.currentTimeMillis()));
        }

        try {
            //properties.setProperty(DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_NAME, getResources().getString(R.string.packagename));//
            //https://bit.ly/2M9bFcC
            //"https://github.com/zytzjx/testfile/raw/master/Application-debug.apk"
            //http://58.213.22.146/dl/Application-debug.apk
            //http://10.1.1.105/devowner.apk
            properties.setProperty(DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION, file_url);
//            String sCheckSum = Base64.encodeToString(digest.digest(), Base64.URL_SAFE).replace("=","");
//            String sCheckSum256 = Base64.encodeToString(digest256.digest(), Base64.URL_SAFE).replace("=","");
//            Log.d("NFCCHECK", sCheckSum);
//            Log.d("NFCCHECK", sCheckSum256);
            String sCheckSum = GetCheckSum(getActivity(),"sha256");
            Log.d("NFCCHECK", sCheckSum);
            properties.setProperty(DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM, sCheckSum);


            properties.setProperty(DevicePolicyManager.EXTRA_PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED, "true");
            properties.setProperty(DevicePolicyManager.EXTRA_PROVISIONING_SKIP_ENCRYPTION, "true");
            properties.setProperty(DevicePolicyManager.EXTRA_PROVISIONING_SKIP_USER_CONSENT, "true");

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        //https://github.com/zytzjx/testfile/raw/master/Application-debug.apk/
        try {
            properties.store(stream, null); //getString(R.string.nfc_comment)
            NdefRecord record = NdefRecord.createMime(
                    DevicePolicyManager.MIME_TYPE_PROVISIONING_NFC, stream.toByteArray());
            return new NdefMessage(new NdefRecord[]{record});
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void onTextChanged(int id, String s) {
        if (mProvisioningValues == null) {
            return;
        }
        switch (id) {
            case R.id.package_name:
                //noinspection deprecation
                mProvisioningValues.put(
                        DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_NAME, s);
                break;
            case R.id.class_name:
                if (Build.VERSION.SDK_INT >= 23) {
                    if (TextUtils.isEmpty(s)) {
                        mProvisioningValues.remove(
                                DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME);
                    } else {
                        // On API 23 and above, we can use
                        // EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME to specify the receiver
                        // in the device owner app. If the provisioning values contain this key,
                        // EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_NAME is not read.
                        String packageName = mEditPackageName.getText().toString();
                        ComponentName name = new ComponentName(packageName, s);
                        mProvisioningValues.put(
                                DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME,
                                name.flattenToShortString());
                    }
                }
                break;
            case R.id.locale:
                //mProvisioningValues.put(DevicePolicyManager.EXTRA_PROVISIONING_LOCALE, s);
                break;
            case R.id.timezone:
                //mProvisioningValues.put(DevicePolicyManager.EXTRA_PROVISIONING_TIME_ZONE, s);
                break;
            case R.id.wifi_ssid:
                mProvisioningValues.put(DevicePolicyManager.EXTRA_PROVISIONING_WIFI_SSID, s);
                SetConfig(getActivity(),DevicePolicyManager.EXTRA_PROVISIONING_WIFI_SSID, s);
                break;
            case R.id.wifi_security_type:
                mProvisioningValues.put(
                        DevicePolicyManager.EXTRA_PROVISIONING_WIFI_SECURITY_TYPE, s);
                SetConfig(getActivity(),DevicePolicyManager.EXTRA_PROVISIONING_WIFI_SECURITY_TYPE, s);
                break;
            case R.id.wifi_password:
                mProvisioningValues.put(DevicePolicyManager.EXTRA_PROVISIONING_WIFI_PASSWORD, s);
                SetConfig(getActivity(),DevicePolicyManager.EXTRA_PROVISIONING_WIFI_PASSWORD, s);
                break;
            case R.id.company:
                mCompany = s;
                gatherAdminExtras(mCompany, mSite, mNFCId);
                SetConfig(getActivity(),"company", s);
                break;
            case R.id.site:
                mSite = s;
                gatherAdminExtras(mCompany, mSite, mNFCId);
                SetConfig(getActivity(),"site", s);
                break;
            case R.id.nfcid:
                mNFCId = s;
                gatherAdminExtras(mCompany, mSite, mNFCId);
                break;
            case R.id.apkname:
                SetConfig(getActivity(), "apkname", s);
                /*if (TextUtils.isEmpty(mNFCId))*/{
                    try {
                        Uri uri = Uri.parse(s);
                        List<String> paths = uri.getPathSegments();
                        if(paths.size()==3){
                            mNFCId = paths.get(1);
                            mEditNfcId.setText(mNFCId);
                            gatherAdminExtras(mCompany, mSite, mNFCId);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                }
                break;
        }
    }

    @Override
    public Loader<Map<String, String>> onCreateLoader(int id, Bundle args) {
        if (id == LOADER_PROVISIONING_VALUES) {
            return new ProvisioningValuesLoader(getActivity());
        }
        return null;
    }

    @Override
    public void onLoadFinished(Loader<Map<String, String>> loader, Map<String, String> values) {
        if (loader.getId() == LOADER_PROVISIONING_VALUES) {
            mProvisioningValues = values;
            //noinspection deprecation
            mEditPackageName.setText(values.get(
                    DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_NAME));
            if (Build.VERSION.SDK_INT >= 23) {
                ComponentName name = ComponentName.unflattenFromString(values.get(
                        DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME));
                mEditClassName.setText(name.getClassName());
            }
            mEditLocale.setText(values.get(DevicePolicyManager.EXTRA_PROVISIONING_LOCALE));
            mEditTimezone.setText(values.get(DevicePolicyManager.EXTRA_PROVISIONING_TIME_ZONE));
            mEditWifiSsid.setText(GetConfig(getActivity(),DevicePolicyManager.EXTRA_PROVISIONING_WIFI_SSID));
            mEditWifiSecurityType.setText(GetConfig(getActivity(),
                    DevicePolicyManager.EXTRA_PROVISIONING_WIFI_SECURITY_TYPE));
            mEditWifiPassword.setText(GetConfig(getActivity(),
                    DevicePolicyManager.EXTRA_PROVISIONING_WIFI_PASSWORD));

            mEditApkName.setText(GetConfig(getActivity(), "apkname"));
            mEditCompany.setText(GetConfig(getActivity(),"company"));
            mEditSite.setText(GetConfig(getActivity(),"site"));
            mchkHide.setChecked(GetConfig(getActivity(),"hidden")==""?false:Boolean.parseBoolean(GetConfig(getActivity(),"hidden")));
        }
    }

    @Override
    public void onLoaderReset(Loader<Map<String, String>> loader) {
        // Do nothing
    }

}
