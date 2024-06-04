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
            System.out.println("Uso: java Part2 <mensagem_prof_c> <assinatura_prof_sigc> <chave_AES_aluno_s> (VALORES EM HEXADECIMAL)");
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

        // Se sim, decifrar a mensagem c com AES (chave s, CBC, PKCS), tendo m = AES^-1(c, s)
        byte[] c = hexStringToByteArray(cHex);
        ExtractBytesResult extractionResults = extractBytes(c, 16);
        byte[] iv = extractionResults.extracted;
        byte[] ciphertext = extractionResults.remaining;
        byte[] keyBytes = hexStringToByteArray(sHex);
        if (keyBytes.length != 16) {
            System.out.println("Chave AES deve ter 16 bytes");
            return;
        }
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] plaintext = cipher.doFinal(ciphertext);
            String m = new String(plaintext, "UTF-8");
            System.out.println("Mensagem decifrada: " + m);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Erro ao decifrar a mensagem");
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

    // Método auxiliar para converter um array de bytes para uma string hexadecimal
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Método auxiliar para extrair os primeiros n bytes de um array de bytes
    public static ExtractBytesResult extractBytes(byte[] input, int n) {
        byte[] extracted = new byte[n];
        byte[] remaining = new byte[input.length - n];
        System.arraycopy(input, 0, extracted, 0, n);
        System.arraycopy(input, n, remaining, 0, input.length - n);
        return new ExtractBytesResult(extracted, remaining);
    }

    // Classe auxiliar para armazenar o resultado da extração
    public static class ExtractBytesResult {
        public byte[] extracted;
        public byte[] remaining;

        public ExtractBytesResult(byte[] extracted, byte[] remaining) {
            this.extracted = extracted;
            this.remaining = remaining;
        }
    }
}
