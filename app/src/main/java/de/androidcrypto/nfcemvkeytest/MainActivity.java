package de.androidcrypto.nfcemvkeytest;

import static de.androidcrypto.nfcemvkeytest.utils.EmvUtils.notEmpty;

import android.annotation.SuppressLint;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import android.util.TypedValue;
import android.view.KeyEvent;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.github.devnied.emvnfccard.model.EmvCard;
import com.github.devnied.emvnfccard.parser.EmvParser;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;

import de.androidcrypto.nfcemvkeytest.ca.RootCa;
import de.androidcrypto.nfcemvkeytest.ca.RootCaManager;
import de.androidcrypto.nfcemvkeytest.keys.CaPublicKey;
import de.androidcrypto.nfcemvkeytest.keys.EmvKeyReader;
import de.androidcrypto.nfcemvkeytest.keys.EmvPublicKey;
import de.androidcrypto.nfcemvkeytest.keys.IssuerIccPublicKey;
import de.androidcrypto.nfcemvkeytest.keys.checks.ROCACheck;
import de.androidcrypto.nfcemvkeytest.provider.Provider;
import de.androidcrypto.nfcemvkeytest.utils.NFCUtils;
import de.androidcrypto.nfcemvkeytest.utils.SimpleAsyncTask;
import fr.devnied.bitlib.BytesUtils;

//import sasc.emv.CA;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    // https://github.com/johnzweng/android-emv-key-test
    // this is a modified version using enableReaderMode

    private static final String TAG = MainActivity.class.getName();
    private NFCUtils nfcUtils;
    private EmvCard mReadCard;

    private TextView statusText;
    private ScrollView scrollView;

    final String TechIsoDep = "android.nfc.tech.IsoDep";
    private NfcAdapter mNfcAdapter;
    private EmvCard card;

    /**
     * IsoDep provider
     */
    private Provider mProvider = new Provider();
    private boolean tipFlag;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        tipFlag = false;
        setContentView(R.layout.activity_main);
        //nfcUtils = new NFCUtils(this);
        statusText = findViewById(R.id.statusText);
        scrollView = findViewById(R.id.scrollView);
        // init known Root CA's from XML file in resources

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }

    /*
    @Override
    protected void onResume() {
        if (!NFCUtils.isNfcAvailable(this)) {
            cleanConsole();
            log("Sorry, this device doesn't seem to support NFC.\nThis app will not work. :-(");
        } else if (!NFCUtils.isNfcEnabled(this)) {
            cleanConsole();
            log("NFC is disabled in system settings.\nPlease enable it and restart this app.");
        } else {
            nfcUtils.enableDispatch();
        }

        // only show once in lifetime of activity and only in 5% of starts (to not be annoying)
        if (!tipFlag && randomlyTrueInXpercent(5)) {
            Toast.makeText(this, getString(R.string.tip_volume_keys), Toast.LENGTH_SHORT).show();
        }
        tipFlag = true;
        super.onResume();
    }
    */

    private boolean randomlyTrueInXpercent(int xPercent) {
        return new Random().nextInt(100) < xPercent;
    }


    /*
        @Override
        protected void onPause() {
            super.onPause();
            nfcUtils.disableDispatch();
        }
        */
/*
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.actionbar, menu);
        return super.onCreateOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here.
        int id = item.getItemId();
        if (id == R.id.action_copy_output) {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = ClipData.newPlainText(getString(R.string.clipboard_label), statusText.getText());
            clipboard.setPrimaryClip(clip);
            Toast toast = Toast.makeText(this, getString(R.string.action_copy_toast), Toast.LENGTH_SHORT);
            toast.show();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
*/
    @Override
    public boolean dispatchKeyEvent(KeyEvent event) {
        int action = event.getAction();
        int keyCode = event.getKeyCode();
        switch (keyCode) {
            case KeyEvent.KEYCODE_VOLUME_UP:
                if (action == KeyEvent.ACTION_DOWN) {
                    float oldSizePx = statusText.getTextSize();
                    statusText.setTextSize(TypedValue.COMPLEX_UNIT_PX, (float) (oldSizePx * 1.1));
                }
                return true;
            case KeyEvent.KEYCODE_VOLUME_DOWN:
                if (action == KeyEvent.ACTION_DOWN) {
                    float oldSizePx = statusText.getTextSize();
                    statusText.setTextSize(TypedValue.COMPLEX_UNIT_PX, (float) (oldSizePx * 0.9));
                }
                return true;
            default:
                return super.dispatchKeyEvent(event);
        }
    }


    @SuppressLint("StaticFieldLeak")
    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        final Tag mTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if (mTag != null) {

            new SimpleAsyncTask() {
                private IsoDep tagIsoDep;
                private EmvCard card;
                private Exception exception;

                @Override
                protected void onPreExecute() {
                    super.onPreExecute();
                    cleanConsole();
                    log("Start reading card. Please wait...");
                }

                @Override
                protected void doInBackground() {
                    tagIsoDep = IsoDep.get(mTag);
                    if (tagIsoDep == null) {
                        log("Couldn't connect to NFC card. Please try again.");
                        return;
                    }
                    exception = null;

                    try {
                        mReadCard = null;
                        // Open connection
                        tagIsoDep.connect();
                        mProvider.setmTagCom(tagIsoDep);
                        EmvParser parser = new EmvParser(mProvider, true);
                        card = parser.readEmvCard();
                    } catch (IOException e) {
                        exception = e;
                    } finally {
                        closeQuietly(tagIsoDep);
                    }
                }

                @Override
                protected void onPostExecute(final Object result) {
                    log("Reading finished.");
                    if (exception == null) {
                        if (card != null) {
                            if (StringUtils.isNotBlank(card.getCardNumber())) {
                                mReadCard = card;
                                printResults();
                            } else {
                                Log.w(TAG, "Reading finished, but cardNumber is null or empty..");
                                log("Sorry, couldn't parse the card data. Is this an EMV banking card?");
                            }
                        } else {
                            Log.w(TAG, "reading finished, no exception but card == null..");
                            log("Sorry, couldn't parse the card (card is null). Is this an EMV banking card?");
                        }
                    } else {
                        Log.w(TAG, "reading finished with exception.");
                        log("Sorry, we got an error while reading: \"" + exception.getLocalizedMessage() +
                                "\"\nDid you remove the card?\n\nPlease try again.");

                    }
                }
            }.execute();
        }
    }

    // new method
    /**
     * section for NFC
     */

    /**
     * This method is run in another thread when a card is discovered
     * This method cannot cannot direct interact with the UI Thread
     * Use `runOnUiThread` method to change the UI from this method
     *
     * @param tag discovered tag
     */
    @Override
    public void onTagDiscovered(Tag tag) {
        runOnUiThread(() -> {
            //etLog.setText("");
            //etData.setText("");
            //aidSelectedForAnalyze = "";
            //aidSelectedForAnalyzeName = "";
        });
        //playPing();
        //writeToUiAppend(etLog, "NFC tag discovered");

        //tagId = tag.getId();
        //writeToUiAppend(etLog, "TagId: " + bytesToHex(tagId));
        String[] techList = tag.getTechList();
        //writeToUiAppend(etLog, "TechList found with these entries:");
        /*
        for (int i = 0; i < techList.length; i++) {
            writeToUiAppend(etLog, techList[i]);
        }

         */
        // the next steps depend on the TechList found on the device
        for (int i = 0; i < techList.length; i++) {
            String tech = techList[i];
            //writeToUiAppend(etLog, "");
            switch (tech) {
                case TechIsoDep: {
                    //writeToUiAppend(etLog, "*** Tech ***");
                    //writeToUiAppend(etLog, "Technology IsoDep");
                    readIsoDep(tag);
                    break;
                }
                default: {
                    // do nothing
                    break;
                }
            }
        }
    }

    private void readIsoDep(Tag tag) {
        Log.i(TAG, "read a tag with IsoDep technology");
        IsoDep nfc = null;
        nfc = IsoDep.get(tag);
        if (nfc != null) {
            // init of the service methods
            //TagValues tv = new TagValues();
            //AidValues aidV = new AidValues();
            //PdolUtil pu = new PdolUtil(nfc);

            try {
                mReadCard = null;
                // Open connection
                nfc.connect();
                mProvider.setmTagCom(nfc);
                EmvParser parser = new EmvParser(mProvider, true);
                card = parser.readEmvCard();
                if (card != null) onPostExecute();
            } catch (IOException e) {
                System.out.println("IOException: " + e.getMessage());
            } finally {
                closeQuietly(nfc);
            }
        }
    }

    private void onPostExecute() {
        log("Reading finished.");
        if (card != null) {
            if (StringUtils.isNotBlank(card.getCardNumber())) {
                mReadCard = card;
                printResults();
            } else {
                Log.w(TAG, "Reading finished, but cardNumber is null or empty..");
                log("Sorry, couldn't parse the card data. Is this an EMV banking card?");
            }
        } else {
            Log.w(TAG, "reading finished, no exception but card == null..");
            log("Sorry, couldn't parse the card (card is null). Is this an EMV banking card?");
        }
    }


    /**
     * Display results on screen and in log.
     * TODO: ugly dump method, clean up, build more beautiful UI, externalize strings.
     */
    private void printResults() {
        try {
            RootCaManager rootCaManager = new RootCaManager(this);
            // RID is first 5 bytes of AID
            final RootCa rootCaForCardScheme = rootCaManager.getCaForRid(mReadCard.getAid().substring(0, 10));
            final CaPublicKey caKey = rootCaForCardScheme.getCaPublicKeyWithIndex(mReadCard.getCaPublicKeyIndex());
            EmvKeyReader keyReader = new EmvKeyReader();

            log("");
            log("-----------------------------");
            log("-----------------------------");
            log("Card details:");
            log("Card scheme: " + rootCaForCardScheme.getCardSchemeName());
            if (mReadCard.getApplicationLabel() != null) {
                log("Application label: " + mReadCard.getApplicationLabel());
            }
            log("Primary account number (PAN): " + mReadCard.getCardNumber());
            log("-----------------------------");
            log("Root CA index: " + mReadCard.getCaPublicKeyIndex());
            if (caKey == null) {
                log("caKey is NULL");
            } else {
                log("caKey algorithm: " + caKey.getAlgorithm());
            }
            log("Root CA key size: " + (caKey.getModulusBytes().length * 8) + " bits " + caKey.getAlgorithm() + " key");
            log("Root CA key Modulus:\n" + BytesUtils.bytesToString(caKey.getModulusBytes()));
            log("Root CA key Exponent: " + BytesUtils.bytesToString(caKey.getPublicExponentBytes()));
            log("Root CA key expiration date: " + formatDate(caKey.getExpirationDate()));
            log("Root CA key ROCA vulnerable: " + ROCACheck.isAffectedByROCA(caKey.getModulus()));
            log("-----------------------------");
            if (notEmpty(mReadCard.getIssuerPublicKeyCertificate()) &&
                    notEmpty(mReadCard.getIssuerPublicKeyExponent())) {
                final IssuerIccPublicKey issuerKey = keyReader.parseIssuerPublicKey(caKey, mReadCard.getIssuerPublicKeyCertificate(),
                        mReadCard.getIssuerPublicKeyRemainder(), mReadCard.getIssuerPublicKeyExponent());
                log("Issuer pubkey size: " + (issuerKey.getModulusBytes().length * 8) + " bits " + issuerKey.getAlgorithm() + " key");
                log("Issuer pubkey Modulus:\n" + BytesUtils.bytesToString(issuerKey.getModulusBytes()));
                log("Issuer pubkey Exponent: " + BytesUtils.bytesToString(issuerKey.getPublicExponentBytes()));
                log("Issuer pubkey expiration date: " + formatDate(issuerKey.getExpirationDate()));
                log("Issuer pubkey is valid: " + keyReader.validateIssuerPublicKey(caKey, mReadCard.getIssuerPublicKeyCertificate(),
                        mReadCard.getIssuerPublicKeyRemainder(), mReadCard.getIssuerPublicKeyExponent()));
                log("Issuer pubkey ROCA vulnerable: " + ROCACheck.isAffectedByROCA(issuerKey.getModulus()));
                log("-----------------------------");
                if (notEmpty(mReadCard.getIccPublicKeyCertificate()) &&
                        notEmpty(mReadCard.getIccPublicKeyExponent())) {
                    final EmvPublicKey iccKey = keyReader.parseIccPublicKey(issuerKey, mReadCard.getIccPublicKeyCertificate(),
                            mReadCard.getIccPublicKeyRemainder(), mReadCard.getIccPublicKeyExponent());
                    log("ICC pubkey size: " + (iccKey.getModulusBytes().length * 8) + " bits " + iccKey.getAlgorithm() + " key");
                    log("ICC pubkey Modulus:\n" + BytesUtils.bytesToString(iccKey.getModulusBytes()));
                    log("ICC pubkey Exponent: " + BytesUtils.bytesToString(iccKey.getPublicExponentBytes()));
                    log("ICC pubkey expiration date: " + formatDate(iccKey.getExpirationDate()));
                    log("ICC pubkey ROCA vulnerable: " + ROCACheck.isAffectedByROCA(iccKey.getModulus()));
                    log("-----------------------------");
                } else {
                    log("Found no ICC key data on card. Cannot parse ICC key.");
                }
            } else {
                log("Found no issuer key data on card. Cannot parse keys.");
            }
            log("-----------------------------");
            log("");
        } catch (Exception e) {
            Log.e(TAG, "Exception catched while key validation.", e);
            logException("Exception catched while key validation:\n", e);
        }
    }

    /**
     * Log exception
     *
     * @param e
     */
    private void logException(String header, Exception e) {
        log(header);
        log(e.getLocalizedMessage() + "\n\n");
        log("-----------------------------");
        log("-----------------------------");
        log("Technical details below:");
        log(ExceptionUtils.getStackTrace(e));
        log("-----------------------------");
        log("-----------------------------");
    }

    /**
     * Empty the text view
     */
    private void cleanConsole() {
        statusText.setText("");
    }

    /**
     * Write to text view on screen and logcat
     *
     * @param msg
     */
    private void log(String msg) {
        Log.i(TAG, msg);
        StringBuffer buf = new StringBuffer(statusText.getText());
        buf.append(msg);
        buf.append("\n");
        statusText.setText(buf);
        // and scroll down to the end
        scrollView.post(new Runnable() {
            public void run() {
                scrollView.smoothScrollTo(0, statusText.getBottom());
            }
        });
    }

    /**
     * Format a date contining only month and year
     *
     * @param monthYear
     * @return date string
     */
    private String formatDate(Date monthYear) {
        SimpleDateFormat sdf = new SimpleDateFormat("MMMM yyyy");
        return sdf.format(monthYear);
    }

    /**
     * Close connection to tag, ignore exceptions
     *
     * @param tagComm
     */
    private void closeQuietly(IsoDep tagComm) {
        try {
            if (tagComm != null) {
                tagComm.close();
            }
        } catch (IOException ioe) {
            // ignore
        }
    }

    /**
     * section for activity workflow - important is the disabling of the ReaderMode when activity is pausing
     */

    private void showWirelessSettings() {
        Toast.makeText(this, "You need to enable NFC", Toast.LENGTH_SHORT).show();
        Intent intent = new Intent(Settings.ACTION_WIRELESS_SETTINGS);
        startActivity(intent);
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {

            if (!mNfcAdapter.isEnabled())
                showWirelessSettings();

            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }

}
