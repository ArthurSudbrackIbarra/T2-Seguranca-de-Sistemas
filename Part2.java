import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
        if (args.length != 3) {
            System.out.println(
                    "Uso: java Part2 <mensagem_prof_c> <assinatura_prof_sigc> <chave_aes_aluno_s> (VALORES EM HEXADECIMAL)");
            return;
        }
        String cHex = args[0];
        BigInteger sigc = new BigInteger(args[1], 16);
        String sHex = args[2];

        // Calcular hc = SHA256(c)
        byte[] hash = sha256FromHexString(cHex);
        if (hash == null) {
            System.out.println("Erro ao calcular hash SHA-256");
            return;
        }
        BigInteger hc = new BigInteger(1, hash);

        // Verificar se hc = sigc^ep mod Np
        if (hc.compareTo(sigc.modPow(Constants.epTeacher, Constants.npTeacher)) != 0) {
            System.out.println("Assinatura inválida");
            return;
        }
        System.out.println("Assinatura válida");

        // Se sim, decifrar a mensagem c com AES (chave s, CBC, PKCS), tendo m =
        // AES^-1(c, s)
        String m;
        try {
            m = decryptAES(cHex, sHex);
            System.out.println("Mensagem decifrada: " + m);
        } catch (Exception e) {
            System.out.println("Erro ao decifrar a mensagem: " + e.getMessage());
            return;
        }
    }

    // Método auxiliar para converter uma string hexadecimal para um array de bytes
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // Método auxiliar para calcular o hash SHA-256 de uma string hexadecimal
    public static byte[] sha256FromHexString(String s) {
        byte[] data = hexStringToByteArray(s);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Método para decifrar a mensagem usando AES
    public static String decryptAES(String cHex, String sHex) throws Exception {
        byte[] cBytes = hexStringToByteArray(cHex);
        byte[] sBytes = hexStringToByteArray(sHex);

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
}
