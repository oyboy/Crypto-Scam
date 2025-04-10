package jmhtests;

import org.example.Cryptor;
import org.junit.jupiter.api.Test;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
/*@BenchmarkMode — определяем режим измерения производительности.
    Mode.Throughput измеряет количество операций в единицу времени;
    Mode.AverageTime — средняя продолжительность выполнения метода.
@OutputTimeUnit — задаём единицу измерения времени для результатов бенчмарка.
@Warmup — указываем количество прогревочных итераций и их продолжительность.
@Measurement — определяем количество измерительных итераций и их продолжительность.
@Fork — указываем нужное количестве разветвлений (повторных выполнений) для каждого бенчмарка.
@Timeout — максимальная продолжительность выполнения для каждой итерации бенчмарка.*/
public class CryptorPerformanceTest {
    private Cryptor cryptor;
    private byte[] key;
    private String testText;

    @Setup
    public void setup() {
        cryptor = new Cryptor();
        key = "PerfTestKey1234567890123456".getBytes();
        testText = "This is a performance test string. ".repeat(100);
    }

    @Benchmark
    public String benchmarkEncryption() {
        return cryptor.encrypt(testText, key);
    }

    @Benchmark
    public String benchmarkDecryption() {
        String encrypted = cryptor.encrypt(testText, key);
        return cryptor.decrypt(encrypted, key);
    }
    @Test
    public void launchBenchmark() throws Exception {
        Options opt = new OptionsBuilder()
                .include(this.getClass().getName() + ".*")
                .build();
        new Runner(opt).run();
    }
}