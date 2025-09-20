import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Container,
  TextField,
  Button,
  Box,
  Typography,
  Paper,
  Divider,
  Alert,
  CircularProgress,
  Grid,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  ToggleButton,
  ToggleButtonGroup,
  Checkbox,
  FormControlLabel,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import JSEncrypt from 'jsencrypt';
import { Buffer } from 'buffer';
import CryptoJS from 'crypto-js';

if (typeof window !== 'undefined' && !window.Buffer) {
  window.Buffer = Buffer;
}

// Utility: Convert ArrayBuffer to hexadecimal string
function arrayBufferToHex(buffer) {
  const byteArray = new Uint8Array(buffer);
  const hexParts = [];
  byteArray.forEach(byte => {
    const hex = byte.toString(16);
    hexParts.push(hex.length === 1 ? '0' + hex : hex);
  });
  return hexParts.join('');
}

// Utility: Convert base64 string to ArrayBuffer
function base64ToArrayBuffer(base64) {
  try {
    const binaryString = atob(base64);
    const length = binaryString.length;
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (e) {
    console.error("Error decoding Base64 to ArrayBuffer:", e);
    throw new Error("Invalid Base64 string for ArrayBuffer conversion.");
  }
}

// Utility: Convert CryptoJS WordArray to Hex string for display
function convertWordArrayToHex(wordArray) {
  const hexString = CryptoJS.enc.Hex.stringify(wordArray);
  return hexString;
}

// Utility: Copy to clipboard
const copyToClipboard = (text) => {
  navigator.clipboard.writeText(text).then(
    () => alert('Copied to clipboard!'),
    (err) => console.error('Failed to copy:', err)
  );
};

// EInvoiceAuth Component
const EInvoiceAuth = ({ setAuthToken, setDecryptedSek, setClientId, setClientSecret, setGstin, setUsername }) => {
  // Input fields
  const [clientId, setLocalClientId] = useState('');
  const [clientSecret, setLocalClientSecret] = useState('');
  const [gstin, setLocalGstin] = useState('');
  const [username, setLocalUsername] = useState('');
  const [password, setPassword] = useState('');
  const [eInvoicePublicKey, setEInvoicePublicKey] = useState('');
  const [forceRefreshAccessToken, setForceRefreshAccessToken] = useState(false);

  // Generated/intermediate values
  const [appKey, setAppKey] = useState('');
  const [rawAppKeyHex, setRawAppKeyHex] = useState('');
  const [rawPayloadJson, setRawPayloadJson] = useState('');
  const [base64EncodedPayload, setBase64EncodedPayload] = useState('');
  const [encryptedPayload, setEncryptedPayload] = useState('');
  const [requestHeaders, setRequestHeaders] = useState('');

  // API response and decryption
  const [apiResponse, setApiResponse] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [receivedSek, setReceivedSek] = useState('');
  const [decryptedSekHex, setDecryptedSekHex] = useState('');
  const [decryptedSekBase64, setDecryptedSekBase64] = useState('');

  // Decryption process visibility
  const [trimmedAppKey, setTrimmedAppKey] = useState('');
  const [trimmedReceivedSek, setTrimmedReceivedSek] = useState('');
  const [keyWordArrayHex, setKeyWordArrayHex] = useState('');
  const [receivedSekHex, setReceivedSekHex] = useState('');

  // Update parent state when authentication is successful
  useEffect(() => {
    if (apiResponse && apiResponse.Status === 1 && apiResponse.Data?.AuthToken && decryptedSekBase64) {
      setAuthToken(apiResponse.Data.AuthToken);
      setDecryptedSek(decryptedSekBase64);
      setClientId(clientId);
      setClientSecret(clientSecret);
      setGstin(gstin);
      setUsername(username);
    }
  }, [apiResponse, decryptedSekBase64, clientId, clientSecret, gstin, username, setAuthToken, setDecryptedSek, setClientId, setClientSecret, setGstin, setUsername]);

  // Automatically populate receivedSek if API response is successful
  useEffect(() => {
    if (apiResponse && apiResponse.Status === 1 && apiResponse.Data?.Sek) {
      setReceivedSek(apiResponse.Data.Sek);
      setDecryptedSekHex('');
      setDecryptedSekBase64('');
    }
  }, [apiResponse]);

  // Step 2: Generate 256-bit AppKey
  const generateAndEncryptAppKey = useCallback(() => {
    try {
      const randomBytes = new Uint8Array(32);
      window.crypto.getRandomValues(randomBytes);
      if (randomBytes.length !== 32) {
        throw new Error(`Generated key length is ${randomBytes.length} bytes, expected 32 bytes (256 bits).`);
      }
      const hexKey = arrayBufferToHex(randomBytes.buffer);
      setRawAppKeyHex(hexKey);
      const base64AppKey = Buffer.from(randomBytes).toString('base64');
      setAppKey(base64AppKey);
      setError(null);
    } catch (err) {
      setError(`Error generating 256-bit AppKey: ${err.message}`);
    }
  }, []);

  // Step 3: Construct and Base64 Encode Payload
  const constructAndEncodePayload = useCallback(() => {
    if (!username || !password || !appKey) {
      setError('Username, Password, and AppKey are required to construct payload.');
      return;
    }
    try {
      const payloadData = {
        Username: username,
        Password: password,
        Appkey: appKey,
        ForceRefreshAccessToken: forceRefreshAccessToken,
      };
      const jsonStr = JSON.stringify(payloadData, null, 2);
      setRawPayloadJson(jsonStr);
      const base64Encoded = Buffer.from(jsonStr).toString('base64');
      setBase64EncodedPayload(base64Encoded);
      setError(null);
    } catch (err) {
      setError(`Error constructing/encoding payload: ${err.message}`);
    }
  }, [username, password, appKey, forceRefreshAccessToken]);

  // Step 4: Encrypt Payload
  const encryptPayload = useCallback(() => {
    if (!base64EncodedPayload || !eInvoicePublicKey) {
      setError('Base64 Encoded Payload and Public Key are required for encryption.');
      return;
    }
    try {
      const encrypt = new JSEncrypt();
      encrypt.setPublicKey(eInvoicePublicKey);
      const encrypted = encrypt.encrypt(base64EncodedPayload);
      if (!encrypted) {
        throw new Error('Encryption failed. Check public key format and payload size.');
      }
      setEncryptedPayload(encrypted);
      setError(null);
    } catch (err) {
      setError(`Error encrypting payload: ${err.message}. Ensure public key is valid and in PEM format.`);
    }
  }, [base64EncodedPayload, eInvoicePublicKey]);

  // Step 5: Construct Request Headers
  const constructHeaders = useCallback(() => {
    if (!clientId || !clientSecret || !gstin) {
      setError('Client ID, Client Secret, and GSTIN are required for headers.');
      return;
    }
    const headers = {
      client_id: clientId,
      client_secret: clientSecret,
      Gstin: gstin,
      'Content-Type': 'application/json',
    };
    setRequestHeaders(JSON.stringify(headers, null, 2));
    setError(null);
  }, [clientId, clientSecret, gstin]);

  // Step 6: Send Authentication Request
  const sendAuthenticationRequest = useCallback(async () => {
    if (!encryptedPayload || !clientId || !clientSecret || !gstin) {
      setError('All prerequisite steps (AppKey, Payload, Encryption, Headers) must be completed.');
      return;
    }
    setLoading(true);
    setError(null);
    setApiResponse(null);
    setReceivedSek('');
    setDecryptedSekHex('');
    setDecryptedSekBase64('');
    setTrimmedAppKey('');
    setTrimmedReceivedSek('');
    setKeyWordArrayHex('');
    setReceivedSekHex('');

    const authUrl = '/eivital/v1.04/auth';
    const requestBody = { Data: encryptedPayload };

    try {
      const headers = {
        client_id: clientId,
        client_secret: clientSecret,
        Gstin: gstin,
        'Content-Type': 'application/json',
      };
      const response = await fetch(authUrl, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(requestBody),
      });
      const data = await response.json();
      if (!response.ok) {
        setError(data.ErrorDetails?.[0]?.ErrorMessage || `HTTP error! Status: ${response.status}`);
        return;
      }
      setApiResponse(data);
    } catch (err) {
      setError(`API Request Failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, [encryptedPayload, clientId, clientSecret, gstin]);

  // Step 7: Decrypt Session Encryption Key (SEK)
  const decryptSek = useCallback(() => {
    setDecryptedSekHex('');
    setDecryptedSekBase64('');
    setError(null);
    setReceivedSekHex('');

    const newTrimmedAppKey = appKey.trim();
    const newTrimmedReceivedSek = receivedSek.trim();

    setTrimmedAppKey(newTrimmedAppKey);
    setTrimmedReceivedSek(newTrimmedReceivedSek);

    if (!newTrimmedAppKey) {
      setError('Your generated AppKey from Step 2 is required to decrypt SEK.');
      return;
    }
    if (!newTrimmedReceivedSek) {
      setError('The encrypted SEK from the API response is required to decrypt.');
      return;
    }

    try {
      let appKeyBuffer = base64ToArrayBuffer(newTrimmedAppKey);
      if (appKeyBuffer.byteLength !== 32) {
        throw new Error(`Decoded AppKey must be 32 bytes (256 bits). Got ${appKeyBuffer.byteLength} bytes.`);
      }
      let encryptedSekBuffer = base64ToArrayBuffer(newTrimmedReceivedSek);
      if (encryptedSekBuffer.byteLength === 0 || encryptedSekBuffer.byteLength % 16 !== 0) {
        throw new Error(`Decoded Encrypted SEK length (${encryptedSekBuffer.byteLength} bytes) must be a non-zero multiple of 16 for AES-ECB decryption.`);
      }

      const keyWordArray = CryptoJS.enc.Base64.parse(newTrimmedAppKey);
      setKeyWordArrayHex(convertWordArrayToHex(keyWordArray));

      const encryptedSekWordArray = CryptoJS.enc.Base64.parse(newTrimmedReceivedSek);
      setReceivedSekHex(convertWordArrayToHex(encryptedSekWordArray));

      const decrypted = CryptoJS.AES.decrypt(newTrimmedReceivedSek, keyWordArray, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7,
      });

      const decryptedHex = decrypted.toString(CryptoJS.enc.Hex);
      if (!decryptedHex) {
        throw new Error('Decryption resulted in an empty or invalid hexadecimal string.');
      }

      const decryptedBase64 = CryptoJS.enc.Hex.parse(decryptedHex).toString(CryptoJS.enc.Base64);
      setDecryptedSekHex(decryptedHex);
      setDecryptedSekBase64(decryptedBase64);
      setError(null);
    } catch (err) {
      setError(`Decryption failed: ${err.message}. Please verify the AppKey and Encrypted SEK.`);
      setDecryptedSekHex('Decryption Failed!');
      setDecryptedSekBase64('');
    }
  }, [appKey, receivedSek]);

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        E-Invoice Authentication Flow
      </Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
        <Typography variant="h5" gutterBottom>1. Input Parameters</Typography>
        <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 2 }}>
          <TextField label="Client ID" value={clientId} onChange={(e) => setLocalClientId(e.target.value)} fullWidth />
          <TextField label="Client Secret" value={clientSecret} onChange={(e) => setLocalClientSecret(e.target.value)} fullWidth />
          <TextField label="GSTIN" value={gstin} onChange={(e) => setLocalGstin(e.target.value)} fullWidth />
          <TextField label="Username (Tax Payer)" value={username} onChange={(e) => setLocalUsername(e.target.value)} fullWidth />
          <TextField label="Password (Tax Payer)" type="password" value={password} onChange={(e) => setPassword(e.target.value)} fullWidth />
          <TextField label="E-Invoice Public Key (PEM)" multiline rows={6} value={eInvoicePublicKey} onChange={(e) => setEInvoicePublicKey(e.target.value)} placeholder="-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----" fullWidth />
          <FormControlLabel control={<Checkbox checked={forceRefreshAccessToken} onChange={(e) => setForceRefreshAccessToken(e.target.checked)} />} label="Force Refresh Access Token (10 mins before expiry)" />
        </Box>
      </Paper>
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">2. Generate 256-bit AppKey</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Button variant="contained" onClick={generateAndEncryptAppKey} sx={{ mb: 2 }}>Generate AppKey</Button>
          {rawAppKeyHex && (
            <Box sx={{ backgroundColor: '#f5f5f5', p: 2, borderRadius: 1, mb: 2, wordBreak: 'break-all' }}>
              <Typography variant="subtitle1">Raw AppKey (Hex, 256 bits):</Typography>
              <Typography sx={{ fontStyle: 'italic', color: 'purple' }}>{rawAppKeyHex}</Typography>
            </Box>
          )}
          {appKey && (
            <Box sx={{ backgroundColor: '#f5f5f5', p: 2, borderRadius: 1, wordBreak: 'break-all' }}>
              <Typography variant="subtitle1">Generated AppKey (Base64, 256 bits):</Typography>
              <Typography sx={{ fontStyle: 'italic', color: 'green' }}>{appKey}</Typography>
            </Box>
          )}
        </AccordionDetails>
      </Accordion>
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">3. Construct & Base64 Encode Request Payload</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Button variant="contained" onClick={constructAndEncodePayload} sx={{ mb: 2 }}>Construct and Encode Payload</Button>
          {rawPayloadJson && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle1">Raw Payload JSON:</Typography>
              <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>{rawPayloadJson}</Paper>
            </Box>
          )}
          {base64EncodedPayload && (
            <Box>
              <Typography variant="subtitle1">Base64 Encoded Payload:</Typography>
              <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', wordBreak: 'break-all', fontFamily: 'monospace' }}>{base64EncodedPayload}</Paper>
            </Box>
          )}
        </AccordionDetails>
      </Accordion>
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">4. Encrypt Base64 Encoded Payload</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Button variant="contained" onClick={encryptPayload} sx={{ mb: 2 }}>Encrypt Payload with Public Key</Button>
          {encryptedPayload && (
            <Box sx={{ backgroundColor: '#f5f5f5', p: 2, borderRadius: 1, wordBreak: 'break-all' }}>
              <Typography variant="subtitle1">Encrypted Payload (Data field):</Typography>
              <Typography sx={{ fontStyle: 'italic', color: 'blue' }}>{encryptedPayload}</Typography>
            </Box>
          )}
        </AccordionDetails>
      </Accordion>
      <Accordion sx={{ mb: 2 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">5. Construct Request Headers</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Button variant="contained" onClick={constructHeaders} sx={{ mb: 2 }}>Construct Headers</Button>
          {requestHeaders && (
            <Box sx={{ backgroundColor: '#f5f5f5', p: 2, borderRadius: 1 }}>
              <Typography variant="subtitle1">Request Headers:</Typography>
              <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>{requestHeaders}</Paper>
            </Box>
          )}
        </AccordionDetails>
      </Accordion>
      <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
        <Typography variant="h5" gutterBottom>6. Send Authentication Request</Typography>
        <Button variant="contained" color="primary" onClick={sendAuthenticationRequest} disabled={loading || !encryptedPayload || !clientId || !clientSecret || !gstin} sx={{ mb: 2 }}>
          {loading ? 'Sending...' : 'Send Authentication Request'}
        </Button>
        {apiResponse && (
          <Box sx={{ mt: 2 }}>
            <Typography variant="h6">API Response:</Typography>
            <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#e8f5e9', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>{JSON.stringify(apiResponse, null, 2)}</Paper>
            {apiResponse.Status === 1 ? (
              <>
                <Alert severity="success" sx={{ mt: 2 }}>Authentication Successful!</Alert>
                <Typography variant="subtitle1" sx={{ mt: 2 }}>AuthToken:</Typography>
                <Paper variant="outlined" sx={{ p: 1, wordBreak: 'break-all', backgroundColor: '#e8f5e9' }}>{apiResponse.Data.AuthToken}</Paper>
                <Typography variant="subtitle1" sx={{ mt: 1 }}>TokenExpiry:</Typography>
                <Paper variant="outlined" sx={{ p: 1, wordBreak: 'break-all', backgroundColor: '#e8f5e9' }}>{apiResponse.Data.TokenExpiry}</Paper>
                <Typography variant="subtitle1" sx={{ mt: 1 }}>Encrypted Session Encryption Key (Sek):</Typography>
                <Paper variant="outlined" sx={{ p: 1, wordBreak: 'break-all', backgroundColor: '#e8f5e9' }}>{apiResponse.Data.Sek}</Paper>
              </>
            ) : (
              <Alert severity="warning" sx={{ mt: 2 }}>
                Authentication Failed:<br />
                Code: {apiResponse.ErrorDetails?.[0]?.ErrorCode}<br />
                Message: {apiResponse.ErrorDetails?.[0]?.ErrorMessage}<br />
                Info: {apiResponse.ErrorDetails?.[0]?.InfoDtls}
              </Alert>
            )}
          </Box>
        )}
      </Paper>
      <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
        <Typography variant="h5" gutterBottom>7. Decrypt Session Encryption Key (SEK)</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          To decrypt the SEK received from the API response, you must use **your generated 256-bit AppKey** (from Step 2).
        </Typography>
        <TextField label="Your Generated AppKey (Base64 Encoded, 256 bits)" value={appKey} fullWidth disabled helperText="This is the 256-bit AppKey (from Step 2) used in your payload and to decrypt the SEK." sx={{ mb: 2 }} />
        <TextField label="Encrypted SEK from API Response" value={receivedSek} fullWidth disabled helperText="This is the 'Sek' value received directly from the API response in Step 6." sx={{ mb: 2 }} />
        <Button variant="contained" onClick={decryptSek} disabled={!appKey || !receivedSek} sx={{ mb: 2 }}>Decrypt SEK</Button>
        {(!appKey || !receivedSek) && (
          <Typography color="error" variant="body2" sx={{ mb: 2 }}>
            Ensure you have generated an AppKey (Step 2) and successfully received an API response with SEK (Step 6).
          </Typography>
        )}
        {trimmedAppKey && (
          <Box sx={{ backgroundColor: '#fff8e1', p: 2, borderRadius: 1, mb: 2 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>Trimmed AppKey (256 bits):</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic', mb: 1 }}>
              // 32-byte (256-bit) symmetric key, generated randomly, encoded in Base64.
            </Typography>
            <Typography sx={{ wordBreak: 'break-all', fontFamily: 'monospace', mb: 2 }}>{trimmedAppKey}</Typography>
            <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>Trimmed Received SEK:</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic', mb: 1 }}>
              // Encrypted Session Encryption Key (SEK) from the e-invoice API, Base64-encoded.
            </Typography>
            <Typography sx={{ wordBreak: 'break-all', fontFamily: 'monospace', mb: 2 }}>{trimmedReceivedSek}</Typography>
            <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>Decryption Key (Hex, 256 bits):</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic', mb: 1 }}>
              // 256-bit AppKey in hex, used with AES-256-ECB for SEK decryption.
            </Typography>
            <Typography sx={{ wordBreak: 'break-all', fontFamily: 'monospace', mb: 2 }}>{keyWordArrayHex}</Typography>
            <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>Encrypted Data (Received SEK) (Hex):</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic', mb: 1 }}>
              // Base64-decoded SEK in hex, to be decrypted with the AppKey.
            </Typography>
            <Typography sx={{ wordBreak: 'break-all', fontFamily: 'monospace' }}>{receivedSekHex}</Typography>
          </Box>
        )}
        {decryptedSekHex && decryptedSekHex !== 'Decryption Failed!' && (
          <Box sx={{ mt: 2 }}>
            <Typography variant="h6" color="primary">Decrypted Session Encryption Key (SEK):</Typography>
            <div>
              <Typography variant="subtitle1" sx={{ mt: 1 }}>Hexadecimal:</Typography>
              <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#c8e6c9', wordBreak: 'break-all', fontFamily: 'monospace' }}>{decryptedSekHex}</Paper>
            </div>
            <div>
              <Typography variant="subtitle1" sx={{ mt: 1 }}>Base64:</Typography>
              <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#c8e6c9', wordBreak: 'break-all', fontFamily: 'monospace' }}>{decryptedSekBase64}</Paper>
            </div>
            <Alert severity="info" sx={{ mt: 1 }}>
              This decrypted SEK is crucial for encrypting subsequent e-invoice request payloads (e.g., generating IRN).
            </Alert>
          </Box>
        )}
        {decryptedSekHex === 'Decryption Failed!' && (
          <Paper variant="outlined" sx={{ p: 2, mt: 2, backgroundColor: '#ffebee', border: '1px solid #ef9a9a', wordBreak: 'break-all' }}>
            <Typography variant="subtitle1" color="error">Decryption Failed!</Typography>
          </Paper>
        )}
      </Paper>
    </Container>
  );
};

// IRNEWayBillGenerator Component
const IRNEWayBillGenerator = () => {
  const [currentMode, setCurrentMode] = useState('authentication');
  const [invoiceJwt, setInvoiceJwt] = useState('');
  const [qrcodeJwt, setQrcodeJwt] = useState('');
  const [decodedInvoiceData, setDecodedInvoiceData] = useState(null);
  const [decodedQrCodeData, setDecodedQrCodeData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [taxSch, setTaxSch] = useState('GST');
  const [supTyp, setSupTyp] = useState('EXPWP');
  const [regRev, setRegRev] = useState('N');
  const [ecmGstin, setEcmGstin] = useState(null);
  const [igstOnIntra, setIgstOnIntra] = useState('N');
  const [docTyp, setDocTyp] = useState('INV');
  const [docNo, setDocNo] = useState('DOC/042989888');
  const [docDt, setDocDt] = useState('25/08/2025');
  const [sellerGstin, setSellerGstin] = useState('36AALCC6633K004');
  const [sellerLglNm, setSellerLglNm] = useState('NIC company pvt ltd');
  const [sellerTrdNm, setSellerTrdNm] = useState('NIC Industries');
  const [sellerAddr1, setSellerAddr1] = useState('5th block, kuvempu layout');
  const [sellerAddr2, setSellerAddr2] = useState('kuvempu layout');
  const [sellerLoc, setSellerLoc] = useState('HYDERABAD');
  const [sellerPin, setSellerPin] = useState('500001');
  const [sellerStcd, setSellerStcd] = useState('36');
  const [sellerPh, setSellerPh] = useState('9000000000');
  const [sellerEm, setSellerEm] = useState('abc@gmail.com');
  const [buyerGstin, setBuyerGstin] = useState('URP');
  const [buyerLglNm, setBuyerLglNm] = useState('XYZ company pvt ltd');
  const [buyerTrdNm, setBuyerTrdNm] = useState('XYZ Industries');
  const [buyerPos, setBuyerPos] = useState('96');
  const [buyerAddr1, setBuyerAddr1] = useState('PO Box 12345');
  const [buyerAddr2, setBuyerAddr2] = useState('Dubai Main Road');
  const [buyerLoc, setBuyerLoc] = useState('DUBAI');
  const [buyerPin, setBuyerPin] = useState('999999');
  const [buyerStcd, setBuyerStcd] = useState('96');
  const [buyerPh, setBuyerPh] = useState('9959728586');
  const [buyerEm, setBuyerEm] = useState('xyz@yahoo.com');
  const [dispNm, setDispNm] = useState('ABC company pvt ltd');
  const [dispAddr1, setDispAddr1] = useState('7th block, kuvempu layout');
  const [dispAddr2, setDispAddr2] = useState('kuvempu layout');
  const [dispLoc, setDispLoc] = useState('HYDERABAD');
  const [dispPin, setDispPin] = useState('500004');
  const [dispStcd, setDispStcd] = useState('36');
  const [shipGstin, setShipGstin] = useState('URP');
  const [shipLglNm, setShipLglNm] = useState('XYZ company pvt ltd');
  const [shipTrdNm, setShipTrdNm] = useState('XYZ Industries');
  const [shipAddr1, setShipAddr1] = useState('PO Box 12345');
  const [shipAddr2, setShipAddr2] = useState('Dubai Main Road');
  const [shipLoc, setShipLoc] = useState('DUBAI');
  const [shipPin, setShipPin] = useState('999999');
  const [shipStcd, setShipStcd] = useState('96');
  const [itemSlNo, setItemSlNo] = useState('1');
  const [itemPrdDesc, setItemPrdDesc] = useState('Rice');
  const [itemIsServc, setItemIsServc] = useState('N');
  const [itemHsnCd, setItemHsnCd] = useState('1001');
  const [itemBarcde, setItemBarcde] = useState('123456');
  const [itemQty, setItemQty] = useState('100');
  const [itemFreeQty, setItemFreeQty] = useState('0');
  const [itemUnit, setItemUnit] = useState('BAG');
  const [itemUnitPrice, setItemUnitPrice] = useState('900');
  const [itemTotAmt, setItemTotAmt] = useState('90000');
  const [itemDiscount, setItemDiscount] = useState('0');
  const [itemPreTaxVal, setItemPreTaxVal] = useState('90000');
  const [itemAssAmt, setItemAssAmt] = useState('90000');
  const [itemGstRt, setItemGstRt] = useState('18');
  const [itemIgstAmt, setItemIgstAmt] = useState('16200');
  const [itemCgstAmt, setItemCgstAmt] = useState('0');
  const [itemSgstAmt, setItemSgstAmt] = useState('0');
  const [itemCesRt, setItemCesRt] = useState('0');
  const [itemCesAmt, setItemCesAmt] = useState('0');
  const [itemCesNonAdvlAmt, setItemCesNonAdvlAmt] = useState('0');
  const [itemStateCesRt, setItemStateCesRt] = useState('0');
  const [itemStateCesAmt, setItemStateCesAmt] = useState('0');
  const [itemStateCesNonAdvlAmt, setItemStateCesNonAdvlAmt] = useState('0');
  const [itemOthChrg, setItemOthChrg] = useState('0');
  const [itemTotItemVal, setItemTotItemVal] = useState('106200');
  const [itemOrdLineRef, setItemOrdLineRef] = useState('3256');
  const [itemOrgCntry, setItemOrgCntry] = useState('IN');
  const [itemPrdSlNo, setItemPrdSlNo] = useState('12345');
  const [itemBchNm, setItemBchNm] = useState('123456');
  const [itemBchExpDt, setItemBchExpDt] = useState('25/08/2025');
  const [itemBchWrDt, setItemBchWrDt] = useState('25/08/2025');
  const [itemAttribNm, setItemAttribNm] = useState('Rice');
  const [itemAttribVal, setItemAttribVal] = useState('10000');
  const [valAssVal, setValAssVal] = useState('90000');
  const [valCgstVal, setValCgstVal] = useState('0');
  const [valSgstVal, setValSgstVal] = useState('0');
  const [valIgstVal, setValIgstVal] = useState('16200');
  const [valCesVal, setValCesVal] = useState('0');
  const [valStCesVal, setValStCesVal] = useState('0');
  const [valDiscount, setValDiscount] = useState('0');
  const [valOthChrg, setValOthChrg] = useState('0');
  const [valRndOffAmt, setValRndOffAmt] = useState('0');
  const [valTotInvVal, setValTotInvVal] = useState('106200');
  const [valTotInvValFc, setValTotInvValFc] = useState('106200');
  const [payNm, setPayNm] = useState('ABCDE');
  const [payAccDet, setPayAccDet] = useState('5697389713210');
  const [payMode, setPayMode] = useState('Cash');
  const [payFinInsBr, setPayFinInsBr] = useState('SBIN11000');
  const [payPayTerm, setPayPayTerm] = useState('100');
  const [payPayInstr, setPayPayInstr] = useState('Gift');
  const [payCrTrn, setPayCrTrn] = useState('test');
  const [payDirDr, setPayDirDr] = useState('test');
  const [payCrDay, setPayCrDay] = useState('100');
  const [payPaidAmt, setPayPaidAmt] = useState('10000');
  const [payPaymtDue, setPayPaymtDue] = useState('488');
  const [invRm, setInvRm] = useState('TEST');
  const [docPerdInvStDt, setDocPerdInvStDt] = useState('31/07/2025');
  const [docPerdInvEndDt, setDocPerdInvEndDt] = useState('31/07/2025');
  const [precDocInvNo, setPrecDocInvNo] = useState('DOC/002989888');
  const [precDocInvDt, setPrecDocInvDt] = useState('31/07/2025');
  const [precDocOthRefNo, setPrecDocOthRefNo] = useState('123456');
  const [contrRecAdvRefr, setContrRecAdvRefr] = useState('Doc/003');
  const [contrRecAdvDt, setContrRecAdvDt] = useState('31/07/2025');
  const [contrTendRefr, setContrTendRefr] = useState('Abc001');
  const [contrContrRefr, setContrContrRefr] = useState('Co123');
  const [contrExtRefr, setContrExtRefr] = useState('Yo456');
  const [contrProjRefr, setContrProjRefr] = useState('Doc-456');
  const [contrPORefr, setContrPORefr] = useState('Doc-7897887744');
  const [contrPORefDt, setContrPORefDt] = useState('31/07/2025');
  const [addlDocUrl, setAddlDocUrl] = useState('https://nicindustries.com/export/docs/SB987654.pdf');
  const [addlDocDocs, setAddlDocDocs] = useState('Shipping Bill');
  const [addlDocInfo, setAddlDocInfo] = useState('Shipping Bill SB987654 dated 25/08/2025 for rice export');
  const [expShipBNo, setExpShipBNo] = useState('SB987654');
  const [expShipBDt, setExpShipBDt] = useState('25/08/2025');
  const [expPort, setExpPort] = useState('INMAA1');
  const [expRefClm, setExpRefClm] = useState('Y');
  const [expForCur, setExpForCur] = useState('USD');
  const [expCntCode, setExpCntCode] = useState('AE');
  const [expExpDuty, setExpExpDuty] = useState('0');
  const [transId, setTransId] = useState('12AWGPV7107B1Z1');
  const [transName, setTransName] = useState('XYZ EXPORTS');
  const [distance, setDistance] = useState('630');
  const [transDocNo, setTransDocNo] = useState('DOC/042989888');
  const [transDocDt, setTransDocDt] = useState('25/08/2025');
  const [vehNo, setVehNo] = useState('TS01AB1234');
  const [vehType, setVehType] = useState('R');
  const [transMode, setTransMode] = useState('1');
  const [irnEwbRawPayload, setIrnEwbRawPayload] = useState('');
  const [irnEwbBase64EncodedPayload, setIrnEwbBase64EncodedPayload] = useState('');
  const [irnEwbEncryptedPayload, setIrnEwbEncryptedPayload] = useState('');
  const [irnEwbLoading, setIrnEwbLoading] = useState(false);
  const [irnEwbError, setIrnEwbError] = useState(null);
  const [irnEwbApiResponse, setIrnEwbApiResponse] = useState(null);
  const [authToken, setAuthToken] = useState('');
  const [decryptedSek, setDecryptedSek] = useState('');
  const [clientId, setClientId] = useState('UFf6Ra1Iy5CcsjuKNE1n3KBjIWSpOUdH');
  const [clientSecret, setClientSecret] = useState('w3Hl7rf64Es2CxG+zyEAaXxHvjmkVnrB');
  const [gstin, setGstin] = useState('36AALCC6633K004');
  const [username, setUsername] = useState('');
  const [decryptedApiResponse, setDecryptedApiResponse] = useState('');
  const [decryptionError, setDecryptionError] = useState(null);
  const [isCryptoJSLoaded, setIsCryptoJSLoaded] = useState(false);
  const [isQRCodeLoaded, setIsQRCodeLoaded] = useState(false);
  const [irn, setIrn] = useState('ba379ace397f3a23b06ddf75c3fd72b12d7790eceea0ff553dee886984296bc7');
  const [ewbRawPayload, setEwbRawPayload] = useState('');
  const [ewbBase64EncodedPayload, setEwbBase64EncodedPayload] = useState('');
  const [ewbEncryptedPayload, setEwbEncryptedPayload] = useState('');
  const [ewbApiResponse, setEwbApiResponse] = useState(null);
  const [ewbDecryptedApiResponse, setEwbDecryptedApiResponse] = useState('');
  const [ewbLoading, setEwbLoading] = useState(false);
  const [ewbError, setEwbError] = useState(null);
  const [expShipAddr1, setExpShipAddr1] = useState('7th block, kuvempu layout');
  const [expShipAddr2, setExpShipAddr2] = useState('kuvempu layout');
  const [expShipLoc, setExpShipLoc] = useState('Bangalore');
  const [expShipPin, setExpShipPin] = useState('562160');
  const [expShipStcd, setExpShipStcd] = useState('29');
  const [irnData, setirnData] = useState('null');
  const cryptoJsRef = useRef(null);
  const qrCodeRef = useRef(null);

  const EWB_API_URL = '/eiewb/v1.03/ewaybill';

  useEffect(() => {
    const script = document.createElement('script');
    script.src = 'https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js';
    script.onload = () => {
      cryptoJsRef.current = window.CryptoJS;
      setIsCryptoJSLoaded(true);
    };
    script.onerror = () => {
      setDecryptionError('Failed to load the decryption library.');
    };
    document.head.appendChild(script);
    return () => document.head.removeChild(script);
  }, []);

  useEffect(() => {
    const script = document.createElement('script');
    script.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';
    script.onload = () => {
      qrCodeRef.current = window.QRCode;
      setIsQRCodeLoaded(true);
    };
    script.onerror = () => {
      setError('Failed to load the QR code library.');
    };
    document.head.appendChild(script);
    return () => document.head.removeChild(script);
  }, []);

  const generateQRCode = (containerId, data) => {
    const container = document.getElementById(containerId);
    if (!container || !isQRCodeLoaded || !qrCodeRef.current) return;
    container.innerHTML = '';
    if (data) {
      new qrCodeRef.current(container, {
        text: typeof data === 'string' ? data : JSON.stringify(data),
        width: 128,
        height: 128,
        colorDark: '#000000',
        colorLight: '#ffffff',
        correctLevel: qrCodeRef.current.CorrectLevel.H,
      });
    }
  };

  const decodeJwt = (token) => {
    if (!token) return null;
    try {
      const [, base64] = token.split('.');
      if (!base64) throw new Error('Invalid JWT');
      const decodedString = atob(base64.replace(/-/g, '+').replace(/_/g, '/')).replace(/[^\x20-\x7E\n\r]/g, '');
      let payload = JSON.parse(decodedString);
      if (payload.data) payload = JSON.parse(payload.data);
      return {
        ...payload,
        AddlDocDtls: Array.isArray(payload.AddlDocDtls) ? payload.AddlDocDtls : [],
        ExpDtls: payload.ExpDtls ?? {},
      };
    } catch (e) {
      return null;
    }
  };

  const handleDecodeSubmit = (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setDecodedInvoiceData(null);
    setDecodedQrCodeData(null);
    if (!invoiceJwt && !qrcodeJwt) {
      setError('Please provide at least one JWT to decode.');
      setLoading(false);
      return;
    }
    const invoiceData = invoiceJwt ? decodeJwt(invoiceJwt) : null;
    const qrcodeData = qrcodeJwt ? decodeJwt(qrcodeJwt) : null;

    setError(
      [
        !invoiceData && invoiceJwt ? 'Failed to decode Signed Invoice JWT.' : '',
        !qrcodeData && qrcodeJwt ? 'Failed to decode QR Code JWT.' : '',
      ]
        .filter(Boolean)
        .join(' ')
    );
    setDecodedInvoiceData(invoiceData);
    setDecodedQrCodeData(qrcodeData);
    setLoading(false);
  };

  const validateEwbInputs = useCallback(() => {
    if (!/^\d{2}\/\d{2}\/\d{4}$/.test(transDocDt)) {
      setEwbError('Invalid date format for Trans Doc Date (DD/MM/YYYY).');
      return false;
    }
    if (Number(distance) < 0) {
      setEwbError('Distance must be a positive number or zero.');
      return false;
    }
    if (!irn|| !transId || !transMode || !transDocNo || !transDocDt || !vehNo || !vehType || !transName || !distance) {
      setEwbError('All E-Way Bill fields are required.');
      return false;
    }
    setEwbError(null);
    return true;
  }, [irn, transId, transMode, transDocNo, transDocDt, vehNo, vehType, transName, distance]);

  const constructEwbPayload = useCallback(() => {
    if (!validateEwbInputs()) return;
    try {
      const payload = {
        Irn: irn,
        Distance: Number(distance),
        TransMode: transMode,
        TransId: transId,
        TransName: transName,
        TransDocDt: transDocDt,
        TransDocNo: transDocNo,
        VehNo: vehNo,
        VehType: vehType,
        ExpShipDtls: {
          Addr1: expShipAddr1,
          Addr2: expShipAddr2,
          Loc: expShipLoc,
          Pin: Number(expShipPin),
          Stcd: expShipStcd,
        },
        DispDtls: {
          Nm: dispNm,
          Addr1: dispAddr1,
          Addr2: dispAddr2,
          Loc: dispLoc,
          Pin: Number(dispPin),
          Stcd: dispStcd,
        },
      };
      setEwbRawPayload(JSON.stringify(payload, null, 2));
      setEwbError(null);
    } catch (err) {
      setEwbError(`Error constructing E-Way Bill payload: ${err.message}`);
    }
  }, [
    irn, distance, transMode, transId, transName, transDocDt, transDocNo, vehNo, vehType,
    expShipAddr1, expShipAddr2, expShipLoc, expShipPin, expShipStcd,
    dispNm, dispAddr1, dispAddr2, dispLoc, dispPin, dispStcd,
    validateEwbInputs,
  ]);

  const base64EncodeEwbPayload = useCallback(() => {
    if (!ewbRawPayload) {
      setEwbError('Raw E-Way Bill Payload is required for Base64 encoding.');
      return;
    }
    try {
      const base64Encoded = btoa(encodeURIComponent(ewbRawPayload).replace(/%([0-9A-F]{2})/g, (_, p1) =>
        String.fromCharCode(`0x${p1}`)
      ));
      if (!/^[A-Za-z0-9+/=]+$/.test(base64Encoded)) throw new Error('Invalid Base64.');
      setEwbBase64EncodedPayload(base64Encoded);
      setEwbError(null);
    } catch (err) {
      setEwbError(`Error Base64 encoding E-Way Bill payload: ${err.message}`);
    }
  }, [ewbRawPayload]);

  const encryptEwbPayload = useCallback(() => {
    if (!isCryptoJSLoaded || !cryptoJsRef.current) {
      setEwbError('Encryption library is not yet loaded.');
      return;
    }
    if (!ewbBase64EncodedPayload || !decryptedSek) {
      setEwbError('Base64 Encoded E-Way Bill Payload and Decrypted SEK are required.');
      return;
    }
    try {
      const crypto = cryptoJsRef.current;
      const aesKey = crypto.enc.Base64.parse(decryptedSek);
      const base64WordArray = crypto.enc.Base64.parse(ewbBase64EncodedPayload);
      const encrypted = crypto.AES.encrypt(base64WordArray, aesKey, {
        mode: crypto.mode.ECB,
        padding: crypto.pad.Pkcs7,
      });
      const encryptedBase64 = encrypted.ciphertext.toString(crypto.enc.Base64);
      if (!/^[A-Za-z0-9+/=]+$/.test(encryptedBase64)) throw new Error('Invalid encrypted output.');
      setEwbEncryptedPayload(encryptedBase64);
      setEwbError(null);
    } catch (err) {
      setEwbError(`Error encrypting E-Way Bill payload: ${err.message}.`);
    }
  }, [ewbBase64EncodedPayload, decryptedSek, isCryptoJSLoaded]);

  const sendEwbRequest = useCallback(async () => {
    if (!ewbEncryptedPayload || !authToken || !clientId || !clientSecret || !gstin || !username) {
      setEwbError('All prerequisites must be provided.');
      setEwbLoading(false);
      return;
    }
    if (!ewbEncryptedPayload.trim()) {
      setEwbError('Encrypted E-Way Bill payload is empty or invalid.');
      setEwbLoading(false);
      return;
    }
    setEwbLoading(true);
    setEwbError(null);
    setEwbApiResponse(null);
    setEwbDecryptedApiResponse('');

    const requestBody = { Data: ewbEncryptedPayload };
    const headers = {
      AuthToken: authToken,
      Gstin: gstin,
      client_id: clientId,
      client_secret: clientSecret,
      user_name: username,
      'Content-Type': 'application/json',
    };

    try {
      const response = await fetch(EWB_API_URL, {
        method: 'POST',
        headers,
        body: JSON.stringify(requestBody),
      });
      const rawResponseText = await response.text();
      if (!rawResponseText.trim()) {
        setEwbError(`API Response Error: Empty response. Status: ${response.status}`);
        return;
      }
      const data = JSON.parse(rawResponseText);
      setEwbApiResponse(data);
      if (data.Status === 1 && data.Data) {
        const decryptedResult = decryptEwbPayload(data.Data);
        if (decryptedResult) {
          setEwbDecryptedApiResponse(decryptedResult);
        } else {
          setEwbError('Failed to decrypt E-Way Bill API response data.');
        }
      } else {
        setEwbError(data.ErrorDetails
          ? data.ErrorDetails.map((err) => `Code: ${err.InfCd}, Desc: ${err.Desc}`).join(' | ')
          : `E-Way Bill generation failed. Status: ${data.Status}`);
      }
    } catch (err) {
      setEwbError(`E-Way Bill API Request Failed: ${err.message}.`);
    } finally {
      setEwbLoading(false);
    }
  }, [ewbEncryptedPayload, authToken, clientId, clientSecret, gstin, username]);

  const decryptEwbPayload = useCallback((encryptedData) => {
    if (!isCryptoJSLoaded || !cryptoJsRef.current || !encryptedData || !decryptedSek) {
      setDecryptionError('Decryption library or required data missing.');
      return null;
    }
    try {
      const crypto = cryptoJsRef.current;
      const aesKey = crypto.enc.Base64.parse(decryptedSek);
      const payloadWordArray = crypto.enc.Base64.parse(encryptedData);
      const decrypted = crypto.AES.decrypt({ ciphertext: payloadWordArray }, aesKey, {
        mode: crypto.mode.ECB,
        padding: crypto.pad.Pkcs7,
      });
      const decryptedText = decrypted.toString(crypto.enc.Utf8);
      return JSON.parse(atob(decryptedText));
    } catch (err) {
      setDecryptionError(`Error decrypting E-Way Bill payload: ${err.message}.`);
      return null;
    }
  }, [isCryptoJSLoaded, decryptedSek]);

  const constructIRNEwbPayload = useCallback(() => {
    const requiredFields = [
      taxSch, supTyp, regRev, igstOnIntra, docTyp, docNo, docDt,
      sellerGstin, sellerLglNm, sellerAddr1, sellerLoc, sellerPin, sellerStcd,
      buyerGstin, buyerLglNm, buyerPos, buyerAddr1, buyerAddr2, buyerLoc, buyerPin, buyerStcd,
      dispNm, dispAddr1, dispLoc, dispPin, dispStcd,
      shipGstin, shipLglNm, shipAddr1, shipLoc, shipPin, shipStcd,
      itemPrdDesc, itemHsnCd, itemQty, itemUnit, itemUnitPrice, itemTotAmt,
      valAssVal, valTotInvVal, transId, transName, distance, transDocNo, transDocDt, vehNo, vehType, transMode,
    ];
    if (requiredFields.some(field => !field)) {
      setIrnEwbError('Please fill all required E-Invoice details.');
      return;
    }
    try {
      const payload = {
        Version: '1.1',
        TranDtls: { TaxSch: taxSch, SupTyp: supTyp, RegRev: regRev, EcmGstin: ecmGstin, IgstOnIntra: igstOnIntra },
        DocDtls: { Typ: docTyp, No: docNo, Dt: docDt },
        SellerDtls: {
          Gstin: sellerGstin, LglNm: sellerLglNm, TrdNm: sellerTrdNm, Addr1: sellerAddr1, Addr2: sellerAddr2,
          Loc: sellerLoc, Pin: parseInt(sellerPin), Stcd: sellerStcd, Ph: sellerPh, Em: sellerEm,
        },
        BuyerDtls: {
          Gstin: buyerGstin, LglNm: buyerLglNm, TrdNm: buyerTrdNm, Pos: buyerPos, Addr1: buyerAddr1,
          Addr2: buyerAddr2, Loc: buyerLoc, Pin: parseInt(buyerPin), Stcd: buyerStcd, Ph: buyerPh, Em: buyerEm,
        },
        DispDtls: { Nm: dispNm, Addr1: dispAddr1, Addr2: dispAddr2, Loc: dispLoc, Pin: parseInt(dispPin), Stcd: dispStcd },
        ShipDtls: {
          Gstin: shipGstin, LglNm: shipLglNm, TrdNm: shipTrdNm, Addr1: shipAddr1, Addr2: shipAddr2,
          Loc: shipLoc, Pin: parseInt(shipPin), Stcd: shipStcd,
        },
        ItemList: [{
          SlNo: itemSlNo, PrdDesc: itemPrdDesc, IsServc: itemIsServc, HsnCd: itemHsnCd, Barcde: itemBarcde,
          Qty: parseFloat(itemQty), FreeQty: parseFloat(itemFreeQty), Unit: itemUnit, UnitPrice: parseFloat(itemUnitPrice),
          TotAmt: parseFloat(itemTotAmt), Discount: parseFloat(itemDiscount), PreTaxVal: parseFloat(itemPreTaxVal),
          AssAmt: parseFloat(itemAssAmt), GstRt: parseFloat(itemGstRt), IgstAmt: parseFloat(itemIgstAmt),
          CgstAmt: parseFloat(itemCgstAmt), SgstAmt: parseFloat(itemSgstAmt), CesRt: parseFloat(itemCesRt),
          CesAmt: parseFloat(itemCesAmt), CesNonAdvlAmt: parseFloat(itemCesNonAdvlAmt), StateCesRt: parseFloat(itemStateCesRt),
          StateCesAmt: parseFloat(itemStateCesAmt), StateCesNonAdvlAmt: parseFloat(itemStateCesNonAdvlAmt),
          OthChrg: parseFloat(itemOthChrg), TotItemVal: parseFloat(itemTotItemVal), OrdLineRef: itemOrdLineRef,
          OrgCntry: itemOrgCntry, PrdSlNo: itemPrdSlNo, BchDtls: { Nm: itemBchNm, ExpDt: itemBchExpDt, WrDt: itemBchWrDt },
          AttribDtls: [{ Nm: itemAttribNm, Val: itemAttribVal }],
        }],
        ValDtls: {
          AssVal: parseFloat(valAssVal), CgstVal: parseFloat(valCgstVal), SgstVal: parseFloat(valSgstVal),
          IgstVal: parseFloat(valIgstVal), CesVal: parseFloat(valCesVal), StCesVal: parseFloat(valStCesVal),
          Discount: parseFloat(valDiscount), OthChrg: parseFloat(valOthChrg), RndOffAmt: parseFloat(valRndOffAmt),
          TotInvVal: parseFloat(valTotInvVal), TotInvValFc: parseFloat(valTotInvValFc),
        },
        PayDtls: {
          Nm: payNm, AccDet: payAccDet, Mode: payMode, FinInsBr: payFinInsBr, PayTerm: payPayTerm,
          PayInstr: payPayInstr, CrTrn: payCrTrn, DirDr: payDirDr, CrDay: parseInt(payCrDay),
          PaidAmt: parseFloat(payPaidAmt), PaymtDue: parseFloat(payPaymtDue),
        },
        RefDtls: {
          InvRm: invRm, DocPerdDtls: { InvStDt: docPerdInvStDt, InvEndDt: docPerdInvEndDt },
          PrecDocDtls: [{ InvNo: precDocInvNo, InvDt: precDocInvDt, OthRefNo: precDocOthRefNo }],
          ContrDtls: [{
            RecAdvRefr: contrRecAdvRefr, RecAdvDt: contrRecAdvDt, TendRefr: contrTendRefr,
            ContrRefr: contrContrRefr, ExtRefr: contrExtRefr, ProjRefr: contrProjRefr,
            PORefr: contrPORefr, PORefDt: contrPORefDt,
          }],
        },
        AddlDocDtls: [{ Url: addlDocUrl, Docs: addlDocDocs, Info: addlDocInfo }],
        ExpDtls: {
          ShipBNo: expShipBNo, ShipBDt: expShipBDt, Port: expPort, RefClm: expRefClm,
          ForCur: expForCur, CntCode: expCntCode, ExpDuty: expExpDuty,
        },
        EwbDtls: {
          TransId: transId, TransName: transName, Distance: parseInt(distance), TransDocNo: transDocNo,
          TransDocDt: transDocDt, VehNo: vehNo, VehType: vehType, TransMode: transMode,
        },
      };
      setIrnEwbRawPayload(JSON.stringify(payload, null, 2));
      setIrnEwbError(null);
    } catch (err) {
      setIrnEwbError(`Error constructing IRN/EWB payload: ${err.message}`);
    }
  }, [
    taxSch, supTyp, regRev, ecmGstin, igstOnIntra, docTyp, docNo, docDt, sellerGstin, sellerLglNm, sellerTrdNm,
    sellerAddr1, sellerAddr2, sellerLoc, sellerPin, sellerStcd, sellerPh, sellerEm, buyerGstin, buyerLglNm,
    buyerTrdNm, buyerPos, buyerAddr1, buyerAddr2, buyerLoc, buyerPin, buyerStcd, buyerPh, buyerEm, dispNm,
    dispAddr1, dispAddr2, dispLoc, dispPin, dispStcd, shipGstin, shipLglNm, shipTrdNm, shipAddr1, shipAddr2,
    shipLoc, shipPin, shipStcd, itemSlNo, itemPrdDesc, itemIsServc, itemHsnCd, itemBarcde, itemQty, itemFreeQty,
    itemUnit, itemUnitPrice, itemTotAmt, itemDiscount, itemPreTaxVal, itemAssAmt, itemGstRt, itemIgstAmt,
    itemCgstAmt, itemSgstAmt, itemCesRt, itemCesAmt, itemCesNonAdvlAmt, itemStateCesRt, itemStateCesAmt,
    itemStateCesNonAdvlAmt, itemOthChrg, itemTotItemVal, itemOrdLineRef, itemOrgCntry, itemPrdSlNo, itemBchNm,
    itemBchExpDt, itemBchWrDt, itemAttribNm, itemAttribVal, valAssVal, valCgstVal, valSgstVal, valIgstVal,
    valCesVal, valStCesVal, valDiscount, valOthChrg, valRndOffAmt, valTotInvVal, valTotInvValFc, payNm,
    payAccDet, payMode, payFinInsBr, payPayTerm, payPayInstr, payCrTrn, payDirDr, payCrDay, payPaidAmt,
    payPaymtDue, invRm, docPerdInvStDt, docPerdInvEndDt, precDocInvNo, precDocInvDt, precDocOthRefNo,
    contrRecAdvRefr, contrRecAdvDt, contrTendRefr, contrContrRefr, contrExtRefr, contrProjRefr, contrPORefr,
    contrPORefDt, addlDocUrl, addlDocDocs, addlDocInfo, expShipBNo, expShipBDt, expPort, expRefClm, expForCur,
    expCntCode, expExpDuty, transId, transName, distance, transDocNo, transDocDt, vehNo, vehType, transMode,
  ]);

  const base64EncodeIRNEwbPayload = useCallback(() => {
    if (!irnEwbRawPayload) {
      setIrnEwbError('Raw IRN/EWB Payload is required for Base64 encoding.');
      return;
    }
    try {
      const base64Encoded = btoa(unescape(encodeURIComponent(irnEwbRawPayload)));
      setIrnEwbBase64EncodedPayload(base64Encoded);
      setIrnEwbError(null);
    } catch (err) {
      setIrnEwbError(`Error Base64 encoding IRN/EWB payload: ${err.message}`);
    }
  }, [irnEwbRawPayload]);

  const encryptIRNEwbPayload = useCallback(() => {
    if (!isCryptoJSLoaded || !cryptoJsRef.current) {
      setIrnEwbError('Encryption library is not yet loaded.');
      return;
    }
    if (!irnEwbBase64EncodedPayload || !decryptedSek) {
      setIrnEwbError('Base64 Encoded IRN/EWB Payload and Decrypted SEK are required.');
      return;
    }
    try {
      const crypto = cryptoJsRef.current;
      const aesKey = crypto.enc.Base64.parse(decryptedSek);
      const parsedPayload = crypto.enc.Base64.parse(irnEwbBase64EncodedPayload);
      const encrypted = crypto.AES.encrypt(parsedPayload, aesKey, {
        mode: crypto.mode.ECB,
        padding: crypto.pad.Pkcs7,
      }).toString();
      if (!encrypted) throw new Error('AES encryption failed.');
      setIrnEwbEncryptedPayload(encrypted);
      setIrnEwbError(null);
    } catch (err) {
      setIrnEwbError(`Error encrypting IRN/EWB payload: ${err.message}.`);
    }
  }, [irnEwbBase64EncodedPayload, decryptedSek, isCryptoJSLoaded]);

  const sendIRNEwbRequest = useCallback(async () => {
    if (!irnEwbEncryptedPayload || !authToken || !clientId || !clientSecret || !gstin || !username) {
      setIrnEwbError('All prerequisites must be provided.');
      setIrnEwbLoading(false);
      return;
    }
    if (!irnEwbEncryptedPayload.trim()) {
      setIrnEwbError('Encrypted IRN/EWB payload is empty or invalid.');
      setIrnEwbLoading(false);
      return;
    }
    setIrnEwbLoading(true);
    setIrnEwbError(null);
    setIrnEwbApiResponse(null);
    setDecryptedApiResponse('');
    setDecryptionError(null);

    const irnEwbApiUrl = '/eicore/v1.03/invoice';
    const requestBody = { Data: irnEwbEncryptedPayload };
    const headers = {
      AuthToken: authToken,
      Gstin: gstin,
      client_id: clientId,
      client_secret: clientSecret,
      user_name: username,
      'Content-Type': 'application/json',
    };

    try {
      const response = await fetch(irnEwbApiUrl, { method: 'POST', headers, body: JSON.stringify(requestBody) });
      const rawResponseText = await response.text();
      if (!rawResponseText.trim()) {
        setIrnEwbError(`API Response Error: Empty response. Status: ${response.status}`);
        return;
      }
      const data = JSON.parse(rawResponseText);
      setIrnEwbApiResponse(data);
      if (data.Status === 1 && data.Data) {
        const decryptedResult = decryptPayload(data.Data);
        if (decryptedResult) {
          setDecryptedApiResponse(decryptedResult);
          if (data.Irn) setIrn(data.Irn);
        } else {
          setIrnEwbError('Failed to decrypt IRN/EWB API response data.');
        }
      } else {
        setIrnEwbError(data.ErrorDetails
          ? data.ErrorDetails.map((err) => `Code: ${err.InfCd}, Desc: ${err.Desc}`).join(' | ')
          : `IRN/E-Way Bill generation failed. Status: ${data.Status}`);
      }
    } catch (err) {
      setIrnEwbError(`IRN/E-Way Bill API Request Failed: ${err.message}.`);
    } finally {
      setIrnEwbLoading(false);
    }
  }, [irnEwbEncryptedPayload, authToken, clientId, clientSecret, gstin, username]);

  const decryptPayload = useCallback((encryptedData) => {
    if (!isCryptoJSLoaded || !cryptoJsRef.current || !encryptedData || !decryptedSek) {
      setDecryptionError('Decryption library or required data missing.');
      return null;
    }
    try {
      const crypto = cryptoJsRef.current;
      const aesKey = crypto.enc.Base64.parse(decryptedSek);
      const decrypted = crypto.AES.decrypt(encryptedData, aesKey, {
        mode: crypto.mode.ECB,
        padding: crypto.pad.Pkcs7, 
      }).toString(crypto.enc.Utf8);
      if (!decrypted) throw new Error('AES decryption failed.');
      let decryptedData = JSON.parse(decrypted);
      if (decryptedData.SignedInvoice) setInvoiceJwt(decryptedData.SignedInvoice);
      if (decryptedData.SignedQRCode) setQrcodeJwt(decryptedData.SignedQRCode);
      
      setCurrentMode('decoder');
      const invoiceData = decryptedData.SignedInvoice ? decodeJwt(decryptedData.SignedInvoice) : null;
      const qrcodeData = decryptedData.SignedQRCode ? decodeJwt(decryptedData.SignedQRCode) : null;
      const irn = decodedQrCodeData ? decodedQrCodeData.Irn : null;
      setError(
        [
          !invoiceData && decryptedData.SignedInvoice ? 'Failed to decode Signed Invoice JWT.' : '',
          !qrcodeData && decryptedData.SignedQRCode ? 'Failed to decode Signed QR Code JWT.' : '',
          !irn && decodedQrCodeData.Irn ? 'Failed to decode irn.' : '',
        ]
          .filter(Boolean)
          .join(' ')
      );
      setDecodedInvoiceData(invoiceData);
      setDecodedQrCodeData(qrcodeData);
      setirnData(irn);
      return JSON.stringify(decryptedData, null, 2);
    } catch (err) {
      setDecryptionError(`Error decrypting payload: ${err.message}.`);
      return null;
    }
  }, [isCryptoJSLoaded, decryptedSek]);

useEffect(() => {
  if (currentMode === 'decoder' && decodedQrCodeData && qrcodeJwt) {
    generateQRCode('qrcode-container', qrcodeJwt);
  } else if (currentMode === 'decoder') {
    generateQRCode('qrcode-container', null);
  } else if (currentMode === 'template') {
    generateQRCode('template-qrcode-container', {
      SellerGstin: '36AALCC6633K005',
      BuyerGstin: 'URP',
      DocNo: 'DOC/042989888',
      DocTyp: 'INV',
      DocDt: '25/08/2025',
      TotInvVal: 106200,
      ItemCnt: 1,
      MainHsnCode: '1001',
      Irn: irn || '5187589e7e0aca3d6feb0fc3d1e6e617f32c3db939683811cab6e35b016cacf8',
      IrnDt: '2025-08-26 17:07:41',
    });
  }
  // Populate Irn to E-Way Bill section when available
  if (irn && currentMode === 'ewaybill') {
    setIrn(irn); // Ensure Irn is set in the E-Way Bill context if not already
  }
}, [currentMode, decodedQrCodeData, qrcodeJwt, irn]);

  const renderContent = () => {
    switch (currentMode) {
      case 'authentication':
        return (
          <EInvoiceAuth
            setAuthToken={setAuthToken}
            setDecryptedSek={setDecryptedSek}
            setClientId={setClientId}
            setClientSecret={setClientSecret}
            setGstin={setGstin}
            setUsername={setUsername}
          />
        );
      case 'generator':
        return (
          <>
            <Typography variant="h4" gutterBottom align="center">E-Invoice Generation</Typography>
            <Typography variant="subtitle1" color="text.secondary" align="center" sx={{ mb: 4 }}>
              Generate E-Invoice (IRN) by entering the required details.
            </Typography>
            {(irnEwbError || ewbError) && <Alert severity="error" sx={{ mb: 2 }}>{irnEwbError || ewbError}</Alert>}
            {decryptionError && <Alert severity="error" sx={{ mb: 2 }}>{decryptionError}</Alert>}
            <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
              <Typography variant="h5" gutterBottom>Phase 1: Authentication Credentials</Typography>
              <Divider sx={{ mb: 2 }} />
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Credentials</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <TextField label="Auth Token" value={authToken} onChange={(e) => setAuthToken(e.target.value)} fullWidth />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField label="GSTIN" value={gstin} onChange={(e) => setGstin(e.target.value)} fullWidth />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField label="Client ID" value={clientId} onChange={(e) => setClientId(e.target.value)} fullWidth />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField label="Client Secret" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} fullWidth />
                    </Grid>
                    <Grid item xs={12}>
                      <TextField label="Username" value={username} onChange={(e) => setUsername(e.target.value)} fullWidth />
                    </Grid>
                    <Grid item xs={12}>
                      <TextField label="Decrypted SEK" value={decryptedSek} onChange={(e) => setDecryptedSek(e.target.value)} fullWidth helperText="Enter the decrypted Session Encryption Key (SEK)." />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
            </Paper>
            <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
              <Typography variant="h5" gutterBottom>Phase 2: Generate E-Invoice (IRN) Payload</Typography>
              <Divider sx={{ mb: 2 }} />
              <Accordion defaultExpanded sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Transaction Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}><TextField label="Tax Scheme" value={taxSch} onChange={(e) => setTaxSch(e.target.value)} fullWidth /></Grid>
                    <Grid item xs={12} sm={6}><TextField label="Supply Type" value={supTyp} onChange={(e) => setSupTyp(e.target.value)} fullWidth /></Grid>
                    <Grid item xs={12} sm={6}><TextField label="Reverse Charge (Y/N)" value={regRev} onChange={(e) => setRegRev(e.target.value)} fullWidth /></Grid>
                    <Grid item xs={12} sm={6}><TextField label="Ecom GSTIN" value={ecmGstin || ''} onChange={(e) => setEcmGstin(e.target.value || null)} fullWidth /></Grid>
                    <Grid item xs={12} sm={6}><TextField label="IGST on Intra (Y/N)" value={igstOnIntra} onChange={(e) => setIgstOnIntra(e.target.value)} fullWidth /></Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Document Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={4}><TextField label="Document Type" value={docTyp} onChange={(e) => setDocTyp(e.target.value)} fullWidth /></Grid>
                    <Grid item xs={12} sm={4}><TextField label="Document No" value={docNo} onChange={(e) => setDocNo(e.target.value)} fullWidth /></Grid>
                    <Grid item xs={12}                     sm={4}>
                      <TextField
                        label="Document Date (DD/MM/YYYY)"
                        value={docDt}
                        onChange={(e) => setDocDt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Seller Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Seller GSTIN"
                        value={sellerGstin}
                        onChange={(e) => setSellerGstin(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Legal Name"
                        value={sellerLglNm}
                        onChange={(e) => setSellerLglNm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Trade Name"
                        value={sellerTrdNm}
                        onChange={(e) => setSellerTrdNm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Address 1"
                        value={sellerAddr1}
                        onChange={(e) => setSellerAddr1(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Address 2"
                        value={sellerAddr2}
                        onChange={(e) => setSellerAddr2(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Location"
                        value={sellerLoc}
                        onChange={(e) => setSellerLoc(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Pincode"
                        value={sellerPin}
                        onChange={(e) => setSellerPin(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="State Code"
                        value={sellerStcd}
                        onChange={(e) => setSellerStcd(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Phone"
                        value={sellerPh}
                        onChange={(e) => setSellerPh(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Email"
                        value={sellerEm}
                        onChange={(e) => setSellerEm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Buyer Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Buyer GSTIN"
                        value={buyerGstin}
                        onChange={(e) => setBuyerGstin(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Legal Name"
                        value={buyerLglNm}
                        onChange={(e) => setBuyerLglNm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Trade Name"
                        value={buyerTrdNm}
                        onChange={(e) => setBuyerTrdNm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Place of Supply"
                        value={buyerPos}
                        onChange={(e) => setBuyerPos(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Address 1"
                        value={buyerAddr1}
                        onChange={(e) => setBuyerAddr1(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Address 2"
                        value={buyerAddr2}
                        onChange={(e) => setBuyerAddr2(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Location"
                        value={buyerLoc}
                        onChange={(e) => setBuyerLoc(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Pincode"
                        value={buyerPin}
                        onChange={(e) => setBuyerPin(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="State Code"
                        value={buyerStcd}
                        onChange={(e) => setBuyerStcd(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Phone"
                        value={buyerPh}
                        onChange={(e) => setBuyerPh(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Email"
                        value={buyerEm}
                        onChange={(e) => setBuyerEm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Dispatch Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Dispatch Name"
                        value={dispNm}
                        onChange={(e) => setDispNm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Address 1"
                        value={dispAddr1}
                        onChange={(e) => setDispAddr1(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Address 2"
                        value={dispAddr2}
                        onChange={(e) => setDispAddr2(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Location"
                        value={dispLoc}
                        onChange={(e) => setDispLoc(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Pincode"
                        value={dispPin}
                        onChange={(e) => setDispPin(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="State Code"
                        value={dispStcd}
                        onChange={(e) => setDispStcd(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Shipping Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Shipping GSTIN"
                        value={shipGstin}
                        onChange={(e) => setShipGstin(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Legal Name"
                        value={shipLglNm}
                        onChange={(e) => setShipLglNm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Trade Name"
                        value={shipTrdNm}
                        onChange={(e) => setShipTrdNm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Address 1"
                        value={shipAddr1}
                        onChange={(e) => setShipAddr1(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Address 2"
                        value={shipAddr2}
                        onChange={(e) => setShipAddr2(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Location"
                        value={shipLoc}
                        onChange={(e) => setShipLoc(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Pincode"
                        value={shipPin}
                        onChange={(e) => setShipPin(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="State Code"
                        value={shipStcd}
                        onChange={(e) => setShipStcd(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Item Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Serial No"
                        value={itemSlNo}
                        onChange={(e) => setItemSlNo(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Product Description"
                        value={itemPrdDesc}
                        onChange={(e) => setItemPrdDesc(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Is Service (Y/N)"
                        value={itemIsServc}
                        onChange={(e) => setItemIsServc(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="HSN Code"
                        value={itemHsnCd}
                        onChange={(e) => setItemHsnCd(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Barcode"
                        value={itemBarcde}
                        onChange={(e) => setItemBarcde(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Quantity"
                        value={itemQty}
                        onChange={(e) => setItemQty(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Free Quantity"
                        value={itemFreeQty}
                        onChange={(e) => setItemFreeQty(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Unit"
                        value={itemUnit}
                        onChange={(e) => setItemUnit(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Unit Price"
                        value={itemUnitPrice}
                        onChange={(e) => setItemUnitPrice(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Total Amount"
                        value={itemTotAmt}
                        onChange={(e) => setItemTotAmt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Discount"
                        value={itemDiscount}
                        onChange={(e) => setItemDiscount(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Pre-Tax Value"
                        value={itemPreTaxVal}
                        onChange={(e) => setItemPreTaxVal(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Assessable Amount"
                        value={itemAssAmt}
                        onChange={(e) => setItemAssAmt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="GST Rate (%)"
                        value={itemGstRt}
                        onChange={(e) => setItemGstRt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="IGST Amount"
                        value={itemIgstAmt}
                        onChange={(e) => setItemIgstAmt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="CGST Amount"
                        value={itemCgstAmt}
                        onChange={(e) => setItemCgstAmt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="SGST Amount"
                        value={itemSgstAmt}
                        onChange={(e) => setItemSgstAmt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Cess Rate (%)"
                        value={itemCesRt}
                        onChange={(e) => setItemCesRt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Cess Amount"
                        value={itemCesAmt}
                        onChange={(e) => setItemCesAmt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Cess Non-Adval Amount"
                        value={itemCesNonAdvlAmt}
                        onChange={(e) => setItemCesNonAdvlAmt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="State Cess Rate (%)"
                        value={itemStateCesRt}
                        onChange={(e) => setItemStateCesRt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="State Cess Amount"
                        value={itemStateCesAmt}
                        onChange={(e) => setItemStateCesAmt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="State Cess Non-Adval Amount"
                        value={itemStateCesNonAdvlAmt}
                        onChange={(e) => setItemStateCesNonAdvlAmt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Other Charges"
                        value={itemOthChrg}
                        onChange={(e) => setItemOthChrg(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Total Item Value"
                        value={itemTotItemVal}
                        onChange={(e) => setItemTotItemVal(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Order Line Reference"
                        value={itemOrdLineRef}
                        onChange={(e) => setItemOrdLineRef(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Origin Country"
                        value={itemOrgCntry}
                        onChange={(e) => setItemOrgCntry(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Product Serial No"
                        value={itemPrdSlNo}
                        onChange={(e) => setItemPrdSlNo(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Batch Name"
                        value={itemBchNm}
                        onChange={(e) => setItemBchNm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Batch Expiry Date (DD/MM/YYYY)"
                        value={itemBchExpDt}
                        onChange={(e) => setItemBchExpDt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Batch Warranty Date (DD/MM/YYYY)"
                        value={itemBchWrDt}
                        onChange={(e) => setItemBchWrDt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Attribute Name"
                        value={itemAttribNm}
                        onChange={(e) => setItemAttribNm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Attribute Value"
                        value={itemAttribVal}
                        onChange={(e) => setItemAttribVal(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Value Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Assessable Value"
                        value={valAssVal}
                        onChange={(e) => setValAssVal(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="CGST Value"
                        value={valCgstVal}
                        onChange={(e) => setValCgstVal(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="SGST Value"
                        value={valSgstVal}
                        onChange={(e) => setValSgstVal(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="IGST Value"
                        value={valIgstVal}
                        onChange={(e) => setValIgstVal(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Cess Value"
                        value={valCesVal}
                        onChange={(e) => setValCesVal(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="State Cess Value"
                        value={valStCesVal}
                        onChange={(e) => setValStCesVal(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Discount"
                        value={valDiscount}
                        onChange={(e) => setValDiscount(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Other Charges"
                        value={valOthChrg}
                        onChange={(e) => setValOthChrg(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Round Off Amount"
                        value={valRndOffAmt}
                        onChange={(e) => setValRndOffAmt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Total Invoice Value"
                        value={valTotInvVal}
                        onChange={(e) => setValTotInvVal(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Total Invoice Value (Foreign Currency)"
                        value={valTotInvValFc}
                        onChange={(e) => setValTotInvValFc(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Payment Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Payee Name"
                        value={payNm}
                        onChange={(e) => setPayNm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Account Details"
                        value={payAccDet}
                        onChange={(e) => setPayAccDet(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Mode"
                        value={payMode}
                        onChange={(e) => setPayMode(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Financial Institution Branch"
                        value={payFinInsBr}
                        onChange={(e) => setPayFinInsBr(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Payment Terms"
                        value={payPayTerm}
                        onChange={(e) => setPayPayTerm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Payment Instructions"
                        value={payPayInstr}
                        onChange={(e) => setPayPayInstr(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Credit Transfer"
                        value={payCrTrn}
                        onChange={(e) => setPayCrTrn(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Direct Debit"
                        value={payDirDr}
                        onChange={(e) => setPayDirDr(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Credit Days"
                        value={payCrDay}
                        onChange={(e) => setPayCrDay(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Paid Amount"
                        value={payPaidAmt}
                        onChange={(e) => setPayPaidAmt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Payment Due"
                        value={payPaymtDue}
                        onChange={(e) => setPayPaymtDue(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Reference Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12}>
                      <TextField
                        label="Invoice Remarks"
                        value={invRm}
                        onChange={(e) => setInvRm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Invoice Start Date (DD/MM/YYYY)"
                        value={docPerdInvStDt}
                        onChange={(e) => setDocPerdInvStDt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Invoice End Date (DD/MM/YYYY)"
                        value={docPerdInvEndDt}
                        onChange={(e) => setDocPerdInvEndDt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Preceding Invoice No"
                        value={precDocInvNo}
                        onChange={(e) => setPrecDocInvNo(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Preceding Invoice Date (DD/MM/YYYY)"
                        value={precDocInvDt}
                        onChange={(e) => setPrecDocInvDt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Other Reference No"
                        value={precDocOthRefNo}
                        onChange={(e) => setPrecDocOthRefNo(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Receipt Advice Reference"
                        value={contrRecAdvRefr}
                        onChange={(e) => setContrRecAdvRefr(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Receipt Advice Date (DD/MM/YYYY)"
                        value={contrRecAdvDt}
                        onChange={(e) => setContrRecAdvDt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Tender Reference"
                        value={contrTendRefr}
                        onChange={(e) => setContrTendRefr(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Contract Reference"
                        value={contrContrRefr}
                        onChange={(e) => setContrContrRefr(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="External Reference"
                        value={contrExtRefr}
                        onChange={(e) => setContrExtRefr(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Project Reference"
                        value={contrProjRefr}
                        onChange={(e) => setContrProjRefr(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="PO Reference"
                        value={contrPORefr}
                        onChange={(e) => setContrPORefr(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="PO Reference Date (DD/MM/YYYY)"
                        value={contrPORefDt}
                        onChange={(e) => setContrPORefDt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Additional Document Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12}>
                      <TextField
                        label="Document URL"
                        value={addlDocUrl}
                        onChange={(e) => setAddlDocUrl(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12}>
                      <TextField
                        label="Documents"
                        value={addlDocDocs}
                        onChange={(e) => setAddlDocDocs(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12}>
                      <TextField
                        label="Additional Info"
                        value={addlDocInfo}
                        onChange={(e) => setAddlDocInfo(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Export Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Shipping Bill No"
                        value={expShipBNo}
                        onChange={(e) => setExpShipBNo(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Shipping Bill Date (DD/MM/YYYY)"
                        value={expShipBDt}
                        onChange={(e) => setExpShipBDt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Port Code"
                        value={expPort}
                        onChange={(e) => setExpPort(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Refund Claim (Y/N)"
                        value={expRefClm}
                        onChange={(e) => setExpRefClm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Foreign Currency"
                        value={expForCur}
                        onChange={(e) => setExpForCur(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Country Code"
                        value={expCntCode}
                        onChange={(e) => setExpCntCode(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Export Duty"
                        value={expExpDuty}
                        onChange={(e) => setExpExpDuty(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">E-Way Bill Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Transporter ID"
                        value={transId}
                        onChange={(e) => setTransId(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Transporter Name"
                        value={transName}
                        onChange={(e) => setTransName(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Distance"
                        value={distance}
                        onChange={(e) => setDistance(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Trans Doc No"
                        value={transDocNo}
                        onChange={(e) => setTransDocNo(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Trans Doc Date (DD/MM/YYYY)"
                        value={transDocDt}
                        onChange={(e) => setTransDocDt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Vehicle No"
                        value={vehNo}
                        onChange={(e) => setVehNo(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Vehicle Type"
                        value={vehType}
                        onChange={(e) => setVehType(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Transport Mode"
                        value={transMode}
                        onChange={(e) => setTransMode(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Box sx={{ mt: 3 }}>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={constructIRNEwbPayload}
                  sx={{ mr: 2 }}
                  disabled={irnEwbLoading}
                >
                  Construct Payload
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={base64EncodeIRNEwbPayload}
                  sx={{ mr: 2 }}
                  disabled={!irnEwbRawPayload || irnEwbLoading}
                >
                  Base64 Encode
                </Button>
                <Button
                  variant="contained"
                  color="success"
                  onClick={encryptIRNEwbPayload}
                  sx={{ mr: 2 }}
                  disabled={!irnEwbBase64EncodedPayload || irnEwbLoading}
                >
                  Encrypt Payload
                </Button>
                <Button
                  variant="contained"
                  color="info"
                  onClick={sendIRNEwbRequest}
                  disabled={!irnEwbEncryptedPayload || irnEwbLoading}
                >
                  {irnEwbLoading ? 'Sending...' : 'Send IRN Request'}
                </Button>
              </Box>
            </Paper>
            {irnEwbRawPayload && (
              <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
                <Typography variant="h5" gutterBottom>Raw Payload</Typography>
                <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                  {irnEwbRawPayload}
                </Paper>
                <Button
                  variant="outlined"
                  onClick={() => copyToClipboard(irnEwbRawPayload)}
                  sx={{ mt: 2 }}
                >
                  Copy Raw Payload
                </Button>
              </Paper>
            )}
            {irnEwbBase64EncodedPayload && (
              <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
                <Typography variant="h5" gutterBottom>Base64 Encoded Payload</Typography>
                <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                  {irnEwbBase64EncodedPayload}
                </Paper>
                <Button
                  variant="outlined"
                  onClick={() => copyToClipboard(irnEwbBase64EncodedPayload)}
                  sx={{ mt: 2 }}
                >
                  Copy Base64 Payload
                </Button>
              </Paper>
            )}
            {irnEwbEncryptedPayload && (
              <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
                <Typography variant="h5" gutterBottom>Encrypted Payload</Typography>
                <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                  {irnEwbEncryptedPayload}
                </Paper>
                <Button
                  variant="outlined"
                  onClick={() => copyToClipboard(irnEwbEncryptedPayload)}
                  sx={{ mt: 2 }}
                >
                  Copy Encrypted Payload
                </Button>
              </Paper>
            )}
            {irnEwbApiResponse && (
              <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
                <Typography variant="h5" gutterBottom>API Response</Typography>
                <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#e8f5e9', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                  {JSON.stringify(irnEwbApiResponse, null, 2)}
                </Paper>
                {irnEwbApiResponse.Status === 1 ? (
                  <Alert severity="success" sx={{ mt: 2 }}>IRN Generated Successfully!</Alert>
                ) : (
                  <Alert severity="error" sx={{ mt: 2 }}>
                    IRN Generation Failed: {irnEwbApiResponse.ErrorDetails?.map((err) => `Code: ${err.InfCd}, Desc: ${err.Desc}`).join(' | ')}
                  </Alert>
                )}
              </Paper>
            )}
              {decryptedApiResponse && (
                <Box className="mb-4">
                  <Typography variant="subtitle1">Decrypted API Response:</Typography>
                  <Paper className="p-2 bg-green-50 font-mono">{decryptedApiResponse}</Paper>
                </Box>
              )}
              {irn && (
                <Box className="mb-4">
                  <Typography variant="subtitle1">Generated IRN:</Typography>
                  <Paper className="p-2 bg-green-50 font-mono break-all">{irn}</Paper>
                  <Button variant="outlined" onClick={() => setCurrentMode('ewaybill')} className="mt-2">Proceed to E-Way Bill</Button>
                </Box>
              )}
          </>
        );
      case 'decoder':
        return (
          <>
            <Typography variant="h4" gutterBottom align="center">
              E-Invoice Decoder
            </Typography>
            <Typography variant="subtitle1" color="text.secondary" align="center" sx={{ mb: 4 }}>
              Decode E-Invoice or QR Code JWT to view details.
            </Typography>
            {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
            <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
              <Typography variant="h5" gutterBottom>Input JWTs</Typography>
              <Divider sx={{ mb: 2 }} />
              <Box component="form" onSubmit={handleDecodeSubmit}>
                <Grid container spacing={2}>
                  <Grid item xs={12}>
                    <TextField
                      label="Signed Invoice JWT"
                      value={invoiceJwt}
                      onChange={(e) => setInvoiceJwt(e.target.value)}
                      multiline
                      rows={4}
                      fullWidth
                      helperText="Paste the Signed Invoice JWT here."
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      label="QR Code JWT"
                      value={qrcodeJwt}
                      onChange={(e) => setQrcodeJwt(e.target.value)}
                      multiline
                      rows={4}
                      fullWidth
                      helperText="Paste the QR Code JWT here."
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <Button
                      type="submit"
                      variant="contained"
                      color="primary"
                      disabled={loading || (!invoiceJwt && !qrcodeJwt)}
                    >
                      {loading ? 'Decoding...' : 'Decode JWTs'}
                    </Button>
                  </Grid>
                </Grid>
              </Box>
            </Paper>
            {(decodedInvoiceData || decodedQrCodeData) && (
              <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
                <Typography variant="h5" gutterBottom>Decoded Results</Typography>
                <Divider sx={{ mb: 2 }} />
                {decodedInvoiceData && (
                  <Box sx={{ mb: 3 }}>
                    <Typography variant="h6">Signed Invoice Data</Typography>
                    <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                      {JSON.stringify(decodedInvoiceData, null, 2)}
                    </Paper>
                    <Button
                      variant="outlined"
                      onClick={() => copyToClipboard(JSON.stringify(decodedInvoiceData, null, 2))}
                      sx={{ mt: 2 }}
                    >
                      Copy Invoice Data
                    </Button>
                  </Box>
                )}
                {decodedQrCodeData && (
                  <Box>
                    <Typography variant="h6">QR Code Data</Typography>
                    <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                      {JSON.stringify(decodedQrCodeData, null, 2)}
                    </Paper>
                    <Box id="qrcode-container" sx={{ mt: 2, textAlign: 'center' }} />
                    <Button
                      variant="outlined"
                      onClick={() => copyToClipboard(JSON.stringify(decodedQrCodeData, null, 2))}
                      sx={{ mt: 2 }}
                    >
                      Copy QR Code Data
                    </Button>
                  </Box>
                )}
              </Paper>
            )}
          </>
        );
      case 'template':
        return (
          <>
            <Typography variant="h4" gutterBottom align="center">
              E-Invoice Template
            </Typography>
            <Typography variant="subtitle1" color="text.secondary" align="center" sx={{ mb: 4 }}>
              View a sample E-Invoice QR Code template.
            </Typography>
            <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
              <Typography variant="h5" gutterBottom>Sample QR Code Data</Typography>
              <Divider sx={{ mb: 2 }} />
              <Box id="template-qrcode-container" sx={{ mb: 2, textAlign: 'center' }} />
              <Typography variant="body1" sx={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                {JSON.stringify(
                  {
                    SellerGstin: '36AALCC6633K005',
                    BuyerGstin: 'URP',
                    DocNo: 'DOC/042989888',
                    DocTyp: 'INV',
                    DocDt: '25/08/2025',
                    TotInvVal: 106200,
                    ItemCnt: 1,
                    MainHsnCode: '1001',
                    Irn: '5187589e7e0aca3d6feb0fc3d1e6e617f32c3db939683811cab6e35b016cacf8',
                    IrnDt: '2025-08-26 17:07:41',
                  },
                  null,
                  2
                )}
              </Typography>
              <Button
                variant="outlined"
                onClick={() => copyToClipboard(JSON.stringify({
                  SellerGstin: '36AALCC6633K005',
                  BuyerGstin: 'URP',
                  DocNo: 'DOC/042989888',
                  DocTyp: 'INV',
                  DocDt: '25/08/2025',
                  TotInvVal: 106200,
                  ItemCnt: 1,
                  MainHsnCode: '1001',
                  Irn: '5187589e7e0aca3d6feb0fc3d1e6e617f32c3db939683811cab6e35b016cacf8',
                  IrnDt: '2025-08-26 17:07:41',
                }, null, 2))}
                sx={{ mt: 2 }}
              >
                Copy Template Data
              </Button>
            </Paper>
          </>
        );
      case 'ewaybill':
        return (
          <>
            <Typography variant="h4" gutterBottom align="center">
              E-Way Bill Generation
            </Typography>
            <Typography variant="subtitle1" color="text.secondary" align="center" sx={{ mb: 4 }}>
              Generate E-Way Bill by entering the required details.
            </Typography>
            {ewbError && <Alert severity="error" sx={{ mb: 2 }}>{ewbError}</Alert>}
            {decryptionError && <Alert severity="error" sx={{ mb: 2 }}>{decryptionError}</Alert>}
            <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
              <Typography variant="h5" gutterBottom>Phase 1: Authentication Credentials</Typography>
              <Divider sx={{ mb: 2 }} />
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Credentials</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="IRN"
                        value={irn}
                        onChange={(e) => setIrn(e.target.value)}
                        fullWidth
                        disabled={!!irn}
                        helperText={irn ? 'IRN from E-Invoice' : 'Enter IRN'}
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="GSTIN"
                        value={gstin}
                        onChange={(e) => setGstin(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Client ID"
                        value={clientId}
                        onChange={(e) => setClientId(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        label="Client Secret"
                        value={clientSecret}
                        onChange={(e) => setClientSecret(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12}>
                      <TextField
                        label="Username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12}>
                      <TextField
                        label="Decrypted SEK"
                        value={decryptedSek}
                        onChange={(e) => setDecryptedSek(e.target.value)}
                        fullWidth
                        helperText="Enter the decrypted Session Encryption Key (SEK)."
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
            </Paper>
            <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
              <Typography variant="h5" gutterBottom>Phase 2: E-Way Bill Details</Typography>
              <Divider sx={{ mb: 2 }} />
              <Accordion defaultExpanded sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">E-Way Bill Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12}>
                      <TextField
                        label="IRN"
                        value={irnData}
                        onChange={(e) => setIrn(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Transporter ID"
                        value={transId}
                        onChange={(e) => setTransId(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Transporter Name"
                        value={transName}
                        onChange={(e) => setTransName(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Distance"
                        value={distance}
                        onChange={(e) => setDistance(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Trans Doc No"
                        value={transDocNo}
                        onChange={(e) => setTransDocNo(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Trans Doc Date (DD/MM/YYYY)"
                        value={transDocDt}
                        onChange={(e) => setTransDocDt(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Vehicle No"
                        value={vehNo}
                        onChange={(e) => setVehNo(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Vehicle Type"
                        value={vehType}
                        onChange={(e) => setVehType(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Transport Mode"
                        value={transMode}
                        onChange={(e) => setTransMode(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Export Shipping Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Address 1"
                        value={expShipAddr1}
                        onChange={(e) => setExpShipAddr1(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Address 2"
                        value={expShipAddr2}
                        onChange={(e) => setExpShipAddr2(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Location"
                        value={expShipLoc}
                        onChange={(e) => setExpShipLoc(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Pincode"
                        value={expShipPin}
                        onChange={(e) => setExpShipPin(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="State Code"
                        value={expShipStcd}
                        onChange={(e) => setExpShipStcd(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Accordion sx={{ mb: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Dispatch Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Dispatch Name"
                        value={dispNm}
                        onChange={(e) => setDispNm(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Address 1"
                        value={dispAddr1}
                        onChange={(e) => setDispAddr1(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Address 2"
                        value={dispAddr2}
                        onChange={(e) => setDispAddr2(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Location"
                        value={dispLoc}
                        onChange={(e) => setDispLoc(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="Pincode"
                        value={dispPin}
                        onChange={(e) => setDispPin(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                    <Grid item xs={12} sm={4}>
                      <TextField
                        label="State Code"
                        value={dispStcd}
                        onChange={(e) => setDispStcd(e.target.value)}
                        fullWidth
                      />
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
              <Box sx={{ mt: 3 }}>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={constructEwbPayload}
                  sx={{ mr: 2 }}
                  disabled={ewbLoading}
                >
                  Construct Payload
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={base64EncodeEwbPayload}
                  sx={{ mr: 2 }}
                  disabled={!ewbRawPayload || ewbLoading}
                >
                  Base64 Encode
                </Button>
                <Button
                  variant="contained"
                  color="success"
                  onClick={encryptEwbPayload}
                  sx={{ mr: 2 }}
                  disabled={!ewbBase64EncodedPayload || ewbLoading}
                >
                  Encrypt Payload
                </Button>
                <Button
                  variant="contained"
                  color="info"
                  onClick={sendEwbRequest}
                  disabled={!ewbEncryptedPayload || ewbLoading}
                >
                  {ewbLoading ? 'Sending...' : 'Send EWB Request'}
                </Button>
              </Box>
            </Paper>
            {ewbRawPayload && (
              <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
                <Typography variant="h5" gutterBottom>Raw E-Way Bill Payload</Typography>
                <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                  {ewbRawPayload}
                </Paper>
                <Button
                  variant="outlined"
                  onClick={() => copyToClipboard(ewbRawPayload)}
                  sx={{ mt: 2 }}
                >
                  Copy Raw Payload
                </Button>
              </Paper>
            )}
            {ewbBase64EncodedPayload && (
              <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
                <Typography variant="h5" gutterBottom>Base64 Encoded E-Way Bill Payload</Typography>
                <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                  {ewbBase64EncodedPayload}
                </Paper>
                <Button
                  variant="outlined"
                  onClick={() => copyToClipboard(ewbBase64EncodedPayload)}
                  sx={{ mt: 2 }}
                >
                  Copy Base64 Payload
                </Button>
              </Paper>
            )}
            {ewbEncryptedPayload && (
              <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
                <Typography variant="h5" gutterBottom>Encrypted E-Way Bill Payload</Typography>
                <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#f9f9f9', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                  {ewbEncryptedPayload}
                </Paper>
                <Button
                  variant="outlined"
                  onClick={() => copyToClipboard(ewbEncryptedPayload)}
                  sx={{ mt: 2 }}
                >
                  Copy Encrypted Payload
                </Button>
              </Paper>
            )}
            {ewbApiResponse && (
              <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
                <Typography variant="h5" gutterBottom>E-Way Bill API Response</Typography>
                <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#e8f5e9', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                  {JSON.stringify(ewbApiResponse, null, 2)}
                </Paper>
                {ewbApiResponse.Status === 1 ? (
                  <Alert severity="success" sx={{ mt: 2 }}>E-Way Bill Generated Successfully!</Alert>
                ) : (
                  <Alert severity="error" sx={{ mt: 2 }}>
                    E-Way Bill Generation Failed: {ewbApiResponse.ErrorDetails?.map((err) => `Code: ${err.InfCd}, Desc: ${err.Desc}`).join(' | ')}
                  </Alert>
                )}
              </Paper>
            )}
            {ewbDecryptedApiResponse && (
              <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
                <Typography variant="h5" gutterBottom>Decrypted E-Way Bill API Response</Typography>
                <Paper variant="outlined" sx={{ p: 2, backgroundColor: '#e8f5e9', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                  {JSON.stringify(ewbDecryptedApiResponse, null, 2)}
                </Paper>
                <Button
                  variant="outlined"
                  onClick={() => copyToClipboard(JSON.stringify(ewbDecryptedApiResponse, null, 2))}
                  sx={{ mt: 2 }}
                >
                  Copy Decrypted Response
                </Button>
              </Paper>
            )}
          </>
        );
      default:
        return null;
    }
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h3" gutterBottom align="center">
        E-Invoice and E-Way Bill Generator
      </Typography>
      <Box sx={{ display: 'flex', justifyContent: 'center', mb: 4 }}>
        <ToggleButtonGroup
          value={currentMode}
          exclusive
          onChange={(e, newMode) => newMode && setCurrentMode(newMode)}
          aria-label="mode selection"
        >
          <ToggleButton value="authentication" aria-label="authentication">
            Authentication
          </ToggleButton>
          <ToggleButton value="generator" aria-label="generator">
            E-Invoice Generator
          </ToggleButton>
          <ToggleButton value="decoder" aria-label="decoder">
            Decoder
          </ToggleButton>
          <ToggleButton value="template" aria-label="template">
            Template
          </ToggleButton>
          <ToggleButton value="ewaybill" aria-label="ewaybill">
            E-Way Bill
          </ToggleButton>
        </ToggleButtonGroup>
      </Box>
      {renderContent()}
    </Container>
  );
};

export default IRNEWayBillGenerator;