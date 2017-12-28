using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

/// <summary>
/// RSA加解密 使用OpenSSL的公钥加密/私钥解密
/// 支持.net 4.6及.net core 2.0以上
/// </summary>
public class RsaUtils
{
    private HashAlgorithmName _hashAlgorithmName;
    private Encoding _encoding;
    private RSA _rsaInstance;
    private RsaUtils() { }
    public RsaUtils GetInstance(string key, CertificateType certificateType, RSAType rsaType)
    {
        return GetInstance(key, certificateType, rsaType, Encoding.UTF8);
    }
    public RsaUtils GetInstance(string key, CertificateType certificateType, RSAType rsaType, Encoding encoding)
    {
        this._hashAlgorithmName = rsaType == RSAType.RSA ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256;
        this._encoding = encoding;

        switch (certificateType)
        {
            case CertificateType.PublicKey:
                _rsaInstance = CreateRsaByPublicKey(key);
                break;
            case CertificateType.PrivateKey:
                _rsaInstance = CreateRsaByPrivateKey(key);
                break;
            default: return null;
        }
        return this;
    }

    #region 使用私钥签名
    /// <summary>
    /// 使用私钥签名
    /// </summary>
    /// <param name="data">原始数据</param>
    /// <returns></returns>
    public string Sign(string data)
    {
        byte[] dataBytes = _encoding.GetBytes(data);
        var signatureBytes = _rsaInstance.SignData(dataBytes, _hashAlgorithmName, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(signatureBytes);
    }
    #endregion

    #region 使用公钥验证签名
    /// <summary>
    /// 使用公钥验证签名
    /// </summary>
    /// <param name="data">原始数据</param>
    /// <param name="sign">签名</param>
    /// <returns></returns>

    public bool Verify(string data, string sign)
    {
        byte[] dataBytes = _encoding.GetBytes(data);
        byte[] signBytes = Convert.FromBase64String(sign);
        var verify = _rsaInstance.VerifyData(dataBytes, signBytes, _hashAlgorithmName, RSASignaturePadding.Pkcs1);
        return verify;
    }
    #endregion

    #region 解密
    /// <summary>
    /// 私钥解密
    /// </summary>
    /// <param name="cipherText"></param>
    /// <returns></returns>
    public string Decrypt(string cipherText)
    {
        return Encoding.UTF8.GetString(_rsaInstance.Decrypt(Convert.FromBase64String(cipherText), RSAEncryptionPadding.Pkcs1));
    }
    #endregion



    #region 加密
    /// <summary>
    /// 公钥加密
    /// </summary>
    /// <param name="text"></param>
    /// <returns></returns>
    public string Encrypt(string text)
    {
        return Convert.ToBase64String(_rsaInstance.Encrypt(Encoding.UTF8.GetBytes(text), RSAEncryptionPadding.Pkcs1));
    }
    #endregion

    private RSA CreateRsaByPublicKey(string publicKey)
    {
        byte[] seqOid = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
        byte[] seq = new byte[15];
        var x509Key = Convert.FromBase64String(publicKey);
        // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
        using (MemoryStream mem = new MemoryStream(x509Key))
        {
            using (BinaryReader binr = new BinaryReader(mem))  //wrap Memory Stream with BinaryReader for easy reading
            {
                byte bt = 0;
                ushort twobytes = 0;
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();    //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();   //advance 2 bytes
                else
                    return null;
                seq = binr.ReadBytes(15);       //read the Sequence OID
                if (!CompareBytearrays(seq, seqOid))    //make sure Sequence for OID is correct
                    return null;
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
                    binr.ReadByte();    //advance 1 byte
                else if (twobytes == 0x8203)
                    binr.ReadInt16();   //advance 2 bytes
                else
                    return null;
                bt = binr.ReadByte();
                if (bt != 0x00)     //expect null byte next
                    return null;
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();    //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();   //advance 2 bytes
                else
                    return null;
                twobytes = binr.ReadUInt16();
                byte lowbyte = 0x00;
                byte highbyte = 0x00;
                if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
                    lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
                else if (twobytes == 0x8202)
                {
                    highbyte = binr.ReadByte(); //advance 2 bytes
                    lowbyte = binr.ReadByte();
                }
                else
                    return null;
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
                int modsize = BitConverter.ToInt32(modint, 0);
                int firstbyte = binr.PeekChar();
                if (firstbyte == 0x00)
                {   //if first byte (highest order) of modulus is zero, don't include it
                    binr.ReadByte();    //skip this null byte
                    modsize -= 1;   //reduce modulus buffer size by 1
                }
                byte[] modulus = binr.ReadBytes(modsize);   //read the modulus bytes
                if (binr.ReadByte() != 0x02)           //expect an Integer for the exponent data
                    return null;
                int expbytes = (int)binr.ReadByte();       // should only need one byte for actual exponent data (for all useful values)
                byte[] exponent = binr.ReadBytes(expbytes);
                // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                var rsa = RSA.Create();
                RSAParameters rsaKeyInfo = new RSAParameters
                {
                    Modulus = modulus,
                    Exponent = exponent
                };
                rsa.ImportParameters(rsaKeyInfo);
                return rsa;
            }
        }
    }
    private RSA CreateRsaByPrivateKey(string privateKey)
    {
        var privateKeyBits = Convert.FromBase64String(privateKey);
        var rsa = RSA.Create();
        var rsaParameters = new RSAParameters();
        using (BinaryReader binr = new BinaryReader(new MemoryStream(privateKeyBits)))
        {
            byte bt = 0;
            ushort twobytes = 0;
            twobytes = binr.ReadUInt16();
            if (twobytes == 0x8130)
                binr.ReadByte();
            else if (twobytes == 0x8230)
                binr.ReadInt16();
            else
                throw new Exception("Unexpected value read binr.ReadUInt16()");
            twobytes = binr.ReadUInt16();
            if (twobytes != 0x0102)
                throw new Exception("Unexpected version");
            bt = binr.ReadByte();
            if (bt != 0x00)
                throw new Exception("Unexpected value read binr.ReadByte()");
            rsaParameters.Modulus = binr.ReadBytes(GetIntegerSize(binr));
            rsaParameters.Exponent = binr.ReadBytes(GetIntegerSize(binr));
            rsaParameters.D = binr.ReadBytes(GetIntegerSize(binr));
            rsaParameters.P = binr.ReadBytes(GetIntegerSize(binr));
            rsaParameters.Q = binr.ReadBytes(GetIntegerSize(binr));
            rsaParameters.DP = binr.ReadBytes(GetIntegerSize(binr));
            rsaParameters.DQ = binr.ReadBytes(GetIntegerSize(binr));
            rsaParameters.InverseQ = binr.ReadBytes(GetIntegerSize(binr));
        }
        rsa.ImportParameters(rsaParameters);
        return rsa;
    }

    #region 导入密钥算法

    private int GetIntegerSize(BinaryReader binr)
    {
        byte bt = 0;
        int count = 0;
        bt = binr.ReadByte();
        if (bt != 0x02)
            return 0;
        bt = binr.ReadByte();
        if (bt == 0x81)
            count = binr.ReadByte();
        else
        if (bt == 0x82)
        {
            var highbyte = binr.ReadByte();
            var lowbyte = binr.ReadByte();
            byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
            count = BitConverter.ToInt32(modint, 0);
        }
        else
        {
            count = bt;
        }
        while (binr.ReadByte() == 0x00)
        {
            count -= 1;
        }
        binr.BaseStream.Seek(-1, SeekOrigin.Current);
        return count;
    }

    private bool CompareBytearrays(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            return false;
        int i = 0;
        foreach (byte c in a)
        {
            if (c != b[i])
                return false;
            i++;
        }
        return true;
    }
    #endregion


    public enum CertificateType
    {
        PublicKey,
        PrivateKey
    }
    /// <summary>

    /// RSA算法类型

    /// </summary>

    public enum RSAType
    {
        /// <summary>
        /// SHA1
        /// </summary>
        RSA = 0,

        /// <summary>
        /// RSA2 密钥长度至少为2048
        /// SHA256
        /// </summary>
        RSA2
    }
}



