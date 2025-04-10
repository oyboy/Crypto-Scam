import org.example.Cryptor;
import org.junit.jupiter.api.Test;
import org.apache.commons.math3.stat.inference.KolmogorovSmirnovTest;

import java.util.Arrays;
import java.util.BitSet;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class RandomnessTests {
    private static final int SAMPLE_SIZE = 1000000;
    private static final double SIGNIFICANCE_LEVEL = 0.01;

    @Test
    void testFrequencyMonobit() {
        Cryptor cryptor = new Cryptor();
        byte[] key = "RandomTestKey1234567890".getBytes();

        BitSet bits = new BitSet();
        for (int i = 0; i < SAMPLE_SIZE / 8; i++) {
            String text = "sample" + i;
            String encrypted = cryptor.encrypt(text, key);
            byte[] bytes = HexFormat.of().parseHex(encrypted.split("::")[1]);

            for (int j = 0; j < bytes.length && bits.size() < SAMPLE_SIZE; j++) {
                for (int k = 0; k < 8; k++) {
                    bits.set(j * 8 + k, ((bytes[j] >> (7 - k)) & 1) == 1);
                }
            }
        }

        // Тест на монотонность битов (должно быть примерно 50% 0 и 1)
        int onesCount = bits.cardinality();
        double proportion = (double) onesCount / SAMPLE_SIZE;
        assertTrue(Math.abs(proportion - 0.5) < 0.01,
                "Proportion of ones should be close to 0.5 (was " + proportion + ")");
    }

    @Test
    void testRunsTest() {
        Cryptor cryptor = new Cryptor();
        byte[] key = "RandomTestKey1234567890".getBytes();
        BitSet bits = generateLargeBitSample(cryptor, key);

        // Подсчет серий (последовательностей одинаковых битов)
        int runs = 1;
        for (int i = 1; i < SAMPLE_SIZE; i++) {
            if (bits.get(i) != bits.get(i - 1)) {
                runs++;
            }
        }
        // Проверка по критерию Вальда-Вольфовица
        double expectedRuns = (2.0 * bits.cardinality() * (SAMPLE_SIZE - bits.cardinality())) / SAMPLE_SIZE + 1;
        double sigma = Math.sqrt((expectedRuns - 1) * (expectedRuns - 2) / (SAMPLE_SIZE - 1));
        double z = (runs - expectedRuns) / sigma;

        assertTrue(Math.abs(z) < 2.58, // 99% доверительный интервал
                "Runs test failed (z-score = " + z + ")");
    }
    @Test
    void testUniformDistribution() {
        Cryptor cryptor = new Cryptor();
        byte[] key = "RandomTestKey1234567890".getBytes();
        int[] byteCounts = new int[256];
        int totalBytes = 0;
        // Сбор статистики
        for (int i = 0; i < 10000; i++) {
            String encrypted = cryptor.encrypt("sample" + i, key);
            byte[] bytes = HexFormat.of().parseHex(encrypted.split("::")[1]);

            for (byte b : bytes) {
                byteCounts[b & 0xFF]++;
                totalBytes++;
            }
        }
        // Преобразование в эмпирическое распределение
        double[] empiricalDistribution = new double[256];
        for (int i = 0; i < 256; i++) {
            empiricalDistribution[i] = (double) byteCounts[i] / totalBytes;
        }
        // Тест Колмогорова-Смирнова
        KolmogorovSmirnovTest ksTest = new KolmogorovSmirnovTest();
        double[] uniformReference = new double[256];
        Arrays.fill(uniformReference, 1.0/256);

        double pValue = ksTest.kolmogorovSmirnovTest(uniformReference, empiricalDistribution);
        assertTrue(pValue > SIGNIFICANCE_LEVEL,
                "Uniform distribution test failed (p-value = " + pValue + ")");
    }

    private BitSet generateLargeBitSample(Cryptor cryptor, byte[] key) {
        BitSet bits = new BitSet();
        for (int i = 0; i < SAMPLE_SIZE / 8; i++) {
            String text = "sample" + i;
            String encrypted = cryptor.encrypt(text, key);
            byte[] bytes = HexFormat.of().parseHex(encrypted.split("::")[1]);

            for (int j = 0; j < bytes.length && bits.size() < SAMPLE_SIZE; j++) {
                for (int k = 0; k < 8; k++) {
                    bits.set(j * 8 + k, ((bytes[j] >> (7 - k)) & 1) == 1);
                }
            }
        }
        return bits;
    }
}