import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Part2
 */
public class Part2 {

    public static void main(String[] args) {
        // Receber do professor:
        // - uma mensagem c cifrada -> em hexadecimal com IV como 16 primeiros bytes
        // - uma assinatura sigc para a mensagem c -> em hexadecimal
        // Receber do próprio aluno:
        // - a chave AES s -> em hexadecimal
        // - o módulo da chave pública na -> em hexadecimal
        // - a chave privada da -> em hexadecimal
        if (args.length != 5) {
            System.out.println(
                    "\nUso: java Part2 c sigc s na da\n\n"
                            +
                            "Os argumentos devem ser fornecidos em hexadecimal.\n\n" +
                            "c       : A mensagem cifrada recebida do professor.\n" +
                            "sigc    : A assinatura da mensagem cifrada fornecida pelo professor.\n" +
                            "s       : A chave simétrica AES do aluno utilizada para decifrar a mensagem.\n" +
                            "na      : O módulo Na da chave pública do aluno.\n" +
                            "da      : A chave privada da do aluno utilizada para assinar a mensagem.\n");
            return;
        }
        // ! c1 = 04C2A0624E89E24CA506055C60C250BD0D9FE2D595BD69C3065824E7889726184ED550410B50DD2F4506305E95DA56A5A8D9AD04E8B61C300B9B962F7CB537BD0BD58860983FD10C0F36986B8515E0B5
        // ! c2 = 98D4505C63CDBABA768440409CA835EBF3B702B71CDA17FB499B555877E0F11D27A396704B8D209900715A7224285CD012CA4A4736A1D723D882FF900FF3EB6EF6A378C7CAE582CEF71C1E26E1805D99A1CC2C44CB94CD688D94AF72E35CE8F1569318E1E41419D9285B83C62F04CA5CB1A96DDF5A6EC4F484BB039835D969BB
        BigInteger c = new BigInteger(args[0], 16);
        // ! sigc1 = 1043ACDB879B0472C8588EA336DEC8269F99EBF6139D98AB31D1C4657DCB61A4D6DB7AF011186CFF0EC3F19FE4B3AC3CFA2F17E7792F70FA67A1158BCBBC8EB36E5C7F344B63FA71C73EE381E306B52ACA01596BC5C3A5CFFA71A5EC4BF42C3281752866883343E0A60A6943A6EDDEA00CC26A689283F079EE5928014BCFC177472010468005A7BBB7F833EE8E91047BED13E590A34058A2759AB39C4AD99770E9340C5D66716E6FE3BA0310504B8C464393A6A2AAB1D1FDCE736A36F7BE72F2B45EB1A726E0F068EC6CCCCA03D2EBB58C2F5E02EB9BDC09A9108460DB8FFE0194C38157B3E178CC8DFE09B1F8100FFF34C25EC8A6E957D93EA653B55A024833
        // ! sigc2 = 1370EB08C58D8F837EF846ECEAEEB7750DD7B7C15B46AD687BBB068C573CFDAC8DA935C6946BE89C70225E8E676A8250AFC7752B20A19EAACA2993D1F374D118B9E3799CA2722CF2831B1B64A52FEA81C8798F10C1831A49B07708500BFAEBDDAAE3895C4AD6933731095CDB7E598476B2D8832A63D0E3403F357CE37D08D94ECA71E748C9CB3E8257A19158EDF731AF69D41CB160D3B6183615FFD891D9E2AE8D910F541AA2DE5895EDC4997A09CB856D14720094721108A4334098F32ACAFD6E3A588FB6F663455342FE65F9EAC9AAC6EB7ED28BF6ED121E0E6167571CD8C1AC05D2E8EF5F5044B23F905994C68912EF65603C5A30A303BD107AE40C95F397
        BigInteger sigc = new BigInteger(args[1], 16);
        BigInteger s = new BigInteger(args[2], 16);
        BigInteger na = new BigInteger(args[3], 16);
        BigInteger da = new BigInteger(args[4], 16);

        // Calcular hc = SHA256(c)
        byte[] hash = sha256Hash(c);
        if (hash == null) {
            System.out.println("Erro ao calcular hash SHA-256");
            return;
        }
        BigInteger hc = new BigInteger(1, hash);

        // Verificar se hc = sigc^ep mod Np
        if (hc.compareTo(sigc.modPow(Constants.epTeacher, Constants.npTeacher)) != 0) {
            System.out.println("\nAssinatura inválida");
            return;
        }
        System.out.println("\nAssinatura válida");

        // Se sim, decifrar a mensagem c com AES (chave s, CBC, PKCS), tendo m =
        // AES^-1(c, s)
        String m;
        try {
            m = decryptAES(c, s);
            System.out.println("\nMensagem decifrada: " + m + "\n");
        } catch (Exception e) {
            System.out.println("Erro ao decifrar a mensagem: " + e.getMessage());
            return;
        }

        // Inverter a mensagem m decifrada gerando minv. Exemplo, se m = “pucrs”, então
        // minv “srcup”
        String minv = reverseString(m);

        // Gerar um IV aleatório
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        // Cifrar minv usando AES (chave s, CBC, PKCS), tendo cinv = concatenar(IV,
        // AES(minv, s))
        byte[] cipherText;
        try {
            cipherText = encryptAES(minv, s, iv);
        } catch (Exception e) {
            System.out.println("Erro ao cifrar a mensagem: " + e.getMessage());
            return;
        }
        byte[] cinvBytes = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, cinvBytes, 0, iv.length);
        System.arraycopy(cipherText, 0, cinvBytes, iv.length, cipherText.length);
        // ! cinv = 98F9BC7AF9EF72A9D33F164BA01AD919E6A5116958CE96DF0DF4B28B2214F40948A2D174EF57E06EDD3225EFCCA25EC5695D8440E31583FF3DAE4BF759D0930BA744D9F2D304EF93BEDAAA266C662EAE
        // ! cinv2 = CC9C395B2A4A8AB4E95FF5890859E1D9276BF30B467D030C2150DED130355EFD1E2F34BCE804772ECDCE56B4F5BB44C4A7CB681641311CE5208F25AFF95D4289C65FC17A9A13ABE2CDCB7722B2518DCFE6FC18F62B03E17F4DB450B853B90262FF0FA853A005F1E6BA55EC00E1BEA2FFED7501C15C982DA46690372C2E8C3DB7
        BigInteger cinv = new BigInteger(1, cinvBytes);

        // Calcular hinv = SHA256(cinv)
        byte[] hinv = sha256Hash(cinv);

        // Calcular sighinv = hinv^da mod Na
        // ! sighinv = 5CC66CE6C38D1B15FD3C0B3CA4A40186F1654D3502590FB19C8D92F908D7DDDD7A894B607DBC480275C5CAC07296742575A90E85996B6DBDD61FA4F0824064F14EC398808D123223BDB1F6CE90377EA14750F4462EE574BEC8CD7BEC6BEC332FB348C1A109D8E6A583B7880D4E3C8A4890C3F49306BCF3379AF30C6FD236EE3EABE0535AF497489E5660024BBD64244D90FED8AE7AA24B7003A2F9A1D9A764373845218BAD8BE8E0A876B65DB249B233B9613CEE2B7117CC4B4D5F2A13F58A99BAB7A566492DFD3836ABE1EB340AC9D373CAB1F41FDD7C09D44CEF98A1DE99DEFD7F6AA1CE1E323264DFCB2D7D3C8B9DE77C62EE7800DF37D4AFE870FAA0CBEF
        // ! sighinv2 = 599D842E68E984BD5360F8F907FD6E66D0E45F802610407942211463977AC17899F638EA4610BF57A734283533902E8BF98285E37BD4D689905C4797EF6062BEBC7C9EFA7E134AA5D1122BF42CC136FCDED729C8591402AE84214105CB8989877AE42E5138572FA933FEEE813CCE9074204F24B9F79CEFD4B3B7EB8DA93588BA87978FF79DDEB6999D564BBFE8AD84BEF6F8EED244432B1172505A84E1644CE8EE4E8803A3AC6869DA235E78FA0D438365A7AF0E8753745B84E556F38E9684F00386DA834390B72ADC8C6F5F4001EF1CC4A68618E26DC9653CF1D400ECD3CD4BC31C2AFF014F841C90B6B99F933659E6AE50862E47A384722961F8248BF77042
        BigInteger sighinv = new BigInteger(1, hinv).modPow(da, na);

        // Enviar (cinv, sighinv) para o professor -> todos os valores em hexadecimal.
        System.out.println("=== Dados a serem enviados para o professor (em hexadecimal) ===\n");
        System.out.println("cinv: " + bigIntegerToHex(cinv) + "\n");
        System.out.println("sighinv: " + bigIntegerToHex(sighinv));
    }

    // Método auxiliar para converter um BigInteger para um array de bytes
    public static byte[] bigIntegerToByteArray(BigInteger b) {
        byte[] data = b.toByteArray();
        // Se o primeiro byte for 0, remover
        if (data[0] == 0) {
            byte[] tmp = new byte[data.length - 1];
            System.arraycopy(data, 1, tmp, 0, tmp.length);
            return tmp;
        }
        return data;
    }

    // Método auxiliar para calcular o hash SHA-256
    public static byte[] sha256Hash(BigInteger s) {
        byte[] sBytes = bigIntegerToByteArray(s);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(sBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Método para decifrar a mensagem usando AES
    public static String decryptAES(BigInteger c, BigInteger s) throws Exception {
        byte[] cBytes = bigIntegerToByteArray(c);
        byte[] sBytes = bigIntegerToByteArray(s);

        // Verificar o comprimento da chave AES
        if (sBytes.length != 16) {
            throw new IllegalArgumentException("Chave AES deve ter 16 bytes (128 bits)");
        }

        // Extrair IV dos primeiros 16 bytes de cHex
        byte[] ivBytes = new byte[16];
        System.arraycopy(cBytes, 0, ivBytes, 0, 16);

        // Extrair a mensagem cifrada dos bytes restantes
        byte[] cipherTextBytes = new byte[cBytes.length - 16];
        System.arraycopy(cBytes, 16, cipherTextBytes, 0, cipherTextBytes.length);

        // Verificar se o comprimento da mensagem cifrada é múltiplo de 16 bytes
        if (cipherTextBytes.length % 16 != 0) {
            throw new IllegalArgumentException("Comprimento da mensagem cifrada inválido");
        }

        // Configurar o AES para decifrar com CBC e padding PKCS5
        SecretKeySpec secretKeySpec = new SecretKeySpec(sBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);

        // Converter os bytes decifrados para uma string
        return new String(decryptedBytes, "UTF-8");
    }

    // Método para cifrar a mensagem usando AES
    public static byte[] encryptAES(String minv, BigInteger s, byte[] iv) throws Exception {
        byte[] sBytes = bigIntegerToByteArray(s);

        SecretKeySpec secretKeySpec = new SecretKeySpec(sBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(minv.getBytes("UTF-8"));
    }

    // Método auxiliar para inverter uma string
    public static String reverseString(String s) {
        return new StringBuilder(s).reverse().toString();
    }

    // Método auxiliar para receber um BigInteger e retornar o valor em hexadecimal.
    public static String bigIntegerToHex(BigInteger value) {
        return value.toString(16).toUpperCase();
    }
}
