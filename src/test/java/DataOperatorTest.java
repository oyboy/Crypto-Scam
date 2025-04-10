import org.example.DataOperator;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.example.DataOperator.bytesToHex;
import static org.example.DataOperator.hexToBytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class DataOperatorTest {
    @Test
    public void convertionTest(){
        String text = "trash23456789";
        assert Arrays.equals(text.getBytes(), hexToBytes(bytesToHex(text.getBytes())));
    }
    @Test
    public void testXor() {
        byte[] a = {(byte) 0b0000_0000, (byte) 0b1111_1111, (byte) 0b0101_0101};
        byte[] b = {(byte) 0b1111_1111, (byte) 0b0000_0000, (byte) 0b1010_1010};
        byte[] expected = {(byte) 0b1111_1111, (byte) 0b1111_1111, (byte) 0b1111_1111};
        byte[] result = DataOperator.xor(a, b);
        assertArrayEquals(expected, result);
    }

    @Test
    public void testUnionArrays() {
        byte[] a = {0, 1, 2};
        byte[] b = {3, 4, 5};
        byte[] expected = {0, 1, 2, 3, 4, 5};
        byte[] result = DataOperator.unionArrays(a, b);
        assertArrayEquals(expected, result);
    }

    @Test
    public void testUnionArraysWithEmpty() {
        byte[] a = {};
        byte[] b = {1, 2, 3};
        byte[] expected = {1, 2, 3};
        byte[] result = DataOperator.unionArrays(a, b);
        assertArrayEquals(expected, result);

        byte[] result2 = DataOperator.unionArrays(b, a);
        assertArrayEquals(b, result2);
    }

    @Test
    public void testBytesToHex() {
        byte[] bytes = {(byte) 0x00, (byte) 0xFF, (byte) 0x0F, (byte) 0xF0};
        String expected = "00ff0ff0";
        String result = DataOperator.bytesToHex(bytes);
        assertEquals(expected, result);
    }

    @Test
    public void testBytesToHexEmpty() {
        byte[] bytes = {};
        String expected = "";
        String result = DataOperator.bytesToHex(bytes);
        assertEquals(expected, result);
    }

    @Test
    public void testHexToBytes() {
        String hex = "00ff0ff0";
        byte[] expected = {(byte) 0x00, (byte) 0xFF, (byte) 0x0F, (byte) 0xF0};
        byte[] result = DataOperator.hexToBytes(hex);
        assertArrayEquals(expected, result);
    }

    @Test
    public void testHexToBytesEmpty() {
        String hex = "";
        byte[] expected = {};
        byte[] result = DataOperator.hexToBytes(hex);
        assertArrayEquals(expected, result);
    }

    @Test
    public void testBytesToHexAndBack() {
        byte[] original = {(byte) 0x12, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
        String hex = DataOperator.bytesToHex(original);
        byte[] converted = DataOperator.hexToBytes(hex);
        assertArrayEquals(original, converted);
    }
}
