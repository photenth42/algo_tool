package xyz.algotool;

import com.algorand.algosdk.mnemonic.Wordlist;
import com.algorand.algosdk.util.Digester;
import com.algorand.algosdk.util.Encoder;
import com.google.zxing.WriterException;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import java.io.*;
import java.math.BigDecimal;
import java.math.MathContext;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class Retrieval {

    public static int SIZE = 2048;

    public static void main(String[] args) throws WriterException {
        File file = new File("test.txt");
        String acc = null;
        String mnemonic = "";
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            for (String line; (line = br.readLine()) != null; ) {
                if (acc == null) {
                    acc = line;
                } else {
                    mnemonic = line;
                }
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("Looking for " + acc);
        System.out.println("With known Mnemonics: " + mnemonic);

        List<String> words = Arrays.asList(Wordlist.RAW);

        String[] mnemonicsO = mnemonic.split(" ");
        int[] mnemonicInt = new int[24];
        for (int q = 0; q < mnemonicsO.length - 1; q++) {
            mnemonicInt[q] = words.indexOf(mnemonicsO[q]);
        }

        int knownChecksum = words.indexOf(mnemonicsO[24]);

        List<Integer> open = new ArrayList<>();
        for (int q = 0; q < mnemonicsO.length - 1; q++) {
            if (mnemonicInt[q] == -1) {
                open.add(q);
            }
        }

        System.out.println("Missing words at index: " + open.toString());

        int[] openIndex = open.stream().mapToInt(i -> i).toArray();
        int[] wordIndex = new int[openIndex.length];

        final AtomicReference<int[]> last = new AtomicReference<>(wordIndex);
        final AtomicReference<BigDecimal> tested = new AtomicReference<>(BigDecimal.ZERO);
        BigDecimal total = new BigDecimal(2048).pow(openIndex.length);

        final AtomicBoolean found = new AtomicBoolean(false);

        System.out.println("Total possible combinations: " + total.toBigInteger().toString());
        int cores = Runtime.getRuntime().availableProcessors();
        System.out.println("Using all "+cores+" cores...");

        ExecutorService EXEC = Executors.newFixedThreadPool(cores);
        List<Callable<String[]>> tasks = new ArrayList<>();

        final String originalAccount = acc;

        long time = System.currentTimeMillis();

        final AtomicReference<int[]> lastProcessed = new AtomicReference<>(new int[openIndex.length]);

        for (int r = 0; r < cores; r++) {
            final int index = r;
            tasks.add(() -> {
                if (openIndex.length < 3 && index != 0) {
                    return null;
                }
                int[] baseFrom = new int[] {0,0};
                int[] baseTo = new int[] {SIZE-1,SIZE-1};
                List<int[]> baseList = new ArrayList<>();
                createFromTo(baseList, baseFrom, baseTo, 2);
                MessageDigest digest = MessageDigest.getInstance("SHA-512/256");
                KeyPairGenerator gen = KeyPairGenerator.getInstance("Ed25519");
                byte[] temp = new byte[(24 * 11 + 8 - 1) / 8];
                int[] mnemonics = new int[24];
                System.arraycopy(mnemonicInt, 0, mnemonics, 0, 24);
                do {
                    int[] track = null;
                    synchronized (last) {
                        track = Arrays.copyOf(last.get(), openIndex.length);
                        int[] lastIndices =  Arrays.copyOf(track, openIndex.length);;
                        boolean shift = false;
                        for (int q = 2; q < lastIndices.length; q++) {
                            int lastSet = lastIndices[q];
                            if (lastSet < SIZE) {
                                lastIndices[q] = lastIndices[q] + 1;
                                shift = true;
                                break;
                            } else {
                                lastIndices[q] = 0;
                            }
                        }
                        last.set(lastIndices);
                    }

                    for (int[] indices : baseList) {
                        for (int q = 0; q < openIndex.length; q++) {
                            if (q < 2) {
                                mnemonics[openIndex[q]] = indices[q];
                            }else {
                                mnemonics[openIndex[q]] = track[q];
                            }
                        }
                        byte[] arr = toByteArray(temp, mnemonics);
                        int checksum = checksum(digest, Arrays.copyOf(arr, 32));
                        if (knownChecksum != -1 && checksum != knownChecksum) {
                            continue;
                        }
                        String address = getAddress(gen, arr);
                        if (address.equals(originalAccount)) {
                            found.set(true);
                            return toMnemonics(mnemonics);
                        }
                    }
                    synchronized (tested) {
                        BigDecimal bd = tested.get();
                        tested.set(bd.add(new BigDecimal(baseList.size())));
                        lastProcessed.set(track);
                    }
                    if (index == 0) {
                        System.out.println("Last Processed: " + Arrays.toString(lastProcessed.get()));
                        long totalTimeUsedUpToNow = System.currentTimeMillis() - time;
                        BigDecimal timeUsed = new BigDecimal(totalTimeUsedUpToNow);
                        BigDecimal perTest = timeUsed.divide(tested.get(), MathContext.DECIMAL128);
                        BigDecimal totalTimeInMs = perTest.multiply(total).subtract(timeUsed);
                        BigDecimal totalTimeInS = totalTimeInMs.divide(new BigDecimal(1000), MathContext.DECIMAL128);
                        long sec = totalTimeInS.longValue();
                        int hours = (int) (sec / 3600);
                        int minutes = (int) ((sec % 3600) / 60);
                        int seconds = (int) (sec % 60);
                        int days = (int) (hours / 24);
                        hours %= 24;
                        String timeString = String.format("%02d d %02d:%02d:%02d", days, hours, minutes, seconds);
                        System.out.println("Predicted max time: " + timeString);
                    }
//                    openList.clear();
                } while (!found.get());
                return null;
            });
        }


        long start = System.currentTimeMillis();
        List<Future<String[]>> results = null;
        try {
            results = EXEC.invokeAll(tasks);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        EXEC.shutdown();
        long end = System.currentTimeMillis();
        System.out.println("Total Time: "+((end - start)/1000)+" s");
        for (Future<String[]> res : results) {
            try {
                if (res.get() != null) {
                    System.out.println(Arrays.toString(res.get()));
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        }
        System.out.println("Found your account? Finder's fees to ");


        genCode();

    }

    public static void createMore(List<int[]> openList, int[] last, int k, int num) {
        for (int s = 0; s < num; s++) {
            int[] next = new int[last.length];
            System.arraycopy(last, 0, next, 0, next.length);

            boolean shift = false;
            for (int q = 0; q < k; q++) {
                int lastSet = next[q];
                if (lastSet < SIZE) {
                    next[q] = next[q] + 1;
                    shift = true;
                    break;
                } else {
                    next[q] = 0;
                }
            }
            if (shift = false) {
                // no more combinations
                break;
            }
            openList.add(next);
            last = next;
        }
    }

    public static void createFromTo(List<int[]> openList, int[] last, int[] to, int k) {
        do {
            int[] next = new int[last.length];
            System.arraycopy(last, 0, next, 0, next.length);
            boolean shift = false;
            for (int q = 0; q < k; q++) {
                int lastSet = next[q];
                if (lastSet < SIZE-1) {
                    next[q] = next[q] + 1;
                    shift = true;
                    break;
                } else {
                    next[q] = 0;
                }
            }
            if (shift = false) {
                // no more combinations
                break;
            }
            if (Arrays.equals(next, to)) {
                break;
            }
            openList.add(next);
            last = next;
        } while(true);
    }

    public static String[] toMnemonics(int[] arr) {
        return Arrays.stream(arr).mapToObj(i -> (String) Wordlist.RAW[i]).toArray(String[]::new);
    }

    public static byte[] toByteArray(byte[] out, int[] arr) {
        int buffer = 0;
        int numBits = 0;
//        byte[] out = new byte[(arr.length * 11 + 8 - 1) / 8];
        int j = 0;

        for (int i = 0; i < arr.length; ++i) {
            buffer |= arr[i] << numBits;

            for (numBits += 11; numBits >= 8; numBits -= 8) {
                out[j] = (byte) (buffer & 255);
                ++j;
                buffer >>= 8;
            }
        }

        if (numBits != 0) {
            out[j] = (byte) (buffer & 255);
        }

        return out;
    }

    // bottleneck
    static int checksum(MessageDigest digest, byte[] data) {
        digest.reset();
        digest.update(Arrays.copyOf(data, data.length));
        byte[] d = digest.digest();
        d = Arrays.copyOfRange(d, 0, 2);
        return toUintNArray(d)[0];
    }

    private static int[] toUintNArray(byte[] arr) {
        int buffer = 0;
        int numBits = 0;
        int[] out = new int[(arr.length * 8 + 11 - 1) / 11];
        int j = 0;

        for (int i = 0; i < arr.length; ++i) {
            int v = arr[i];
            if (v < 0) {
                v += 256;
            }

            buffer |= v << numBits;
            numBits += 8;
            if (numBits >= 11) {
                out[j] = buffer & 2047;
                ++j;
                buffer >>= 11;
                numBits -= 11;
            }
        }

        if (numBits != 0) {
            out[j] = buffer & 2047;
        }

        return out;
    }

    public static String getAddress(KeyPairGenerator gen, byte[] arr) throws NoSuchAlgorithmException {
        FixedSecureRandom sdf = new FixedSecureRandom(arr);
        gen.initialize(256, sdf);

        var privateKeyPair = gen.generateKeyPair();

        byte[] b = privateKeyPair.getPublic().getEncoded();

        byte[] raw = new byte[32];
        System.arraycopy(b, 12, raw, 0, 32);

        byte[] hashedAddr = Digester.digest(Arrays.copyOf(raw, 32));
        byte[] checksum = Arrays.copyOfRange(hashedAddr, 28, hashedAddr.length);
        byte[] checksumAddr = Arrays.copyOf(raw, raw.length + 4);
        System.arraycopy(checksum, 0, checksumAddr, raw.length, 4);
        String res = Encoder.encodeToBase32StripPad(checksumAddr);
        return res;
    }

    private static class FixedSecureRandom extends SecureRandom {
        private final byte[] fixedValue;
        private int index = 0;

        public FixedSecureRandom(byte[] fixedValue) {
            this.fixedValue = Arrays.copyOf(fixedValue, fixedValue.length);
        }

        public void nextBytes(byte[] bytes) {
            if (this.index < this.fixedValue.length) {
                int len = bytes.length;
                if (len > this.fixedValue.length - this.index) {
                    len = this.fixedValue.length - this.index;
                }

                System.arraycopy(this.fixedValue, this.index, bytes, 0, len);
                this.index += bytes.length;
            }
        }

        public byte[] generateSeed(int numBytes) {
            byte[] bytes = new byte[numBytes];
            this.nextBytes(bytes);
            return bytes;
        }
    }

    class RetrievalProcess implements Callable<String[]> {

        @Override
        public String[] call() throws Exception {
            return new String[0];
        }
    }

    public static void genCode() throws WriterException {
        var out = com.google.zxing.qrcode.encoder.Encoder.encode("algorand://USSLYNN3QWCQICYIUWIMEL7JOERM4ZOZZ5KYIMSEK7WMSATRJCIX2UAWKA", ErrorCorrectionLevel.L);
        StringBuffer buffer = new StringBuffer();
        for (int q = 0; q < out.getMatrix().getHeight(); q+=2) {
            for (int r = 0; r < out.getMatrix().getWidth(); r++) {
                int comb = out.getMatrix().get(r, q) == 1 ? 1 : 0;
                if (q + 1 < out.getMatrix().getHeight()) {
                    comb |= out.getMatrix().get(r, q + 1) == 1 ? 2 : 0;
                }
                switch(comb) {
                    case 0->{
                        buffer.append(" ");
                    }
                    case 1 -> {
                        buffer.append("▀");
                    }
                    case 2 -> {
                        buffer.append("▄");
                    }
                    case 3 -> {
                        buffer.append("█");
                    }
                }
            }
            buffer.append("\n");
        }

        buffer.append("USSLYNN3QWCQICYIUWIMEL7JOERM4ZOZZ5KYIMSEK7WMSATRJCIX2UAWKA");
        System.out.println(buffer);
    }

}
