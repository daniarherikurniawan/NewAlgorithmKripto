import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.Random;

import javax.naming.spi.DirStateFactory.Result;


public class newAlgorithm {
	final static int  blockSize = 16;
	
	/*To encrypt*/
	public static ArrayList<Integer> blockE(String key, ArrayList<Integer> blockPlainText){
		/*To save the cipher text*/
		blockPlainText = commonOperation.shiftLeftPerByte(blockPlainText);
		blockPlainText = feistelEnc(key, blockPlainText);
		blockPlainText = shiftRowOddPerBlock(blockPlainText);
		blockPlainText = sBoxEnc(key, blockPlainText);
		blockPlainText = mixColumnEncPerBlock( blockPlainText);
		blockPlainText = sBoxEnc(key, blockPlainText);
		blockPlainText = shiftRowEvenPerBlock( blockPlainText);
		blockPlainText = feistelEnc(key, blockPlainText);
		blockPlainText = commonOperation.shiftLeftPerByte(blockPlainText);
		
		return blockPlainText;
	}
	
	/*To decrypt*/
	public static ArrayList<Integer> blockD(String key, ArrayList<Integer> blockPlainText){
		/*To save the cipher text*/
		blockPlainText = commonOperation.shiftRightPerByte(blockPlainText);
		blockPlainText = feistelDec(key, blockPlainText);
		blockPlainText = shiftRowEvenPerBlock( blockPlainText);
		blockPlainText = sBoxDec(key, blockPlainText);
		blockPlainText = mixColumnDecPerBlock( blockPlainText);
		blockPlainText = sBoxDec(key, blockPlainText);
		blockPlainText = shiftRowOddPerBlock(blockPlainText);
		blockPlainText = feistelDec(key, blockPlainText);
		blockPlainText = commonOperation.shiftRightPerByte(blockPlainText);
//		
		return blockPlainText;
	}
	
	
	/*S Box for Encryption*/
	public static ArrayList<Integer> sBoxEnc(String key, ArrayList<Integer> blockPlainText){
		/*To save the result*/
		ArrayList<Integer> result = new ArrayList<Integer>();
		
		/*Construct the S Box based on key*/
		ArrayList<Integer> sBox = commonOperation.initiateSBox();
		Collections.shuffle(sBox, new Random(Long.valueOf(commonOperation.count1bit(key))));
		
		/*To process per byte*/
		for (int i = 0; i < blockPlainText.size(); i++) {
			result.add(sBox.get(blockPlainText.get(i)));
		}
		return result;
	}
	
	/*S Box for Encryption*/
	public static ArrayList<Integer> reverseByte(ArrayList<Integer> oriBox){
		/*To save the result*/
		ArrayList<Integer> result = new ArrayList<Integer>();
		result = (ArrayList<Integer>) oriBox.clone();
		
		/*To reverse per byte representation*/
		for (int i = 0; i < oriBox.size(); i++) {
			result.set(oriBox.get(i), i);
		}
		return result;
	}
	
	/*S Box for Decryption*/
	public static ArrayList<Integer> sBoxDec(String key, ArrayList<Integer> blockPlainText){
		/*To save the result*/
		ArrayList<Integer> result = new ArrayList<Integer>();
		
		/*Construct the S Box based on key*/
		ArrayList<Integer> sBox = commonOperation.initiateSBox();
		Collections.shuffle(sBox, new Random(Long.valueOf(commonOperation.count1bit(key))));
		sBox = reverseByte(sBox);
		/*To process per byte*/
		for (int i = 0; i < blockPlainText.size(); i++) {
			result.add(sBox.get(blockPlainText.get(i)));
		}
		return result;
	}
	
	public static ArrayList<Integer> feistelEnc(String key, ArrayList<Integer> input){
		ArrayList<Integer> result= new ArrayList<Integer>();
		result = (ArrayList<Integer>) input.clone();
		if (input.size() == 1)
			return input;
		/*Doing XOR the left side*/
		/*Prepare the key that match the length of the block*/
		String keyStr = key.substring(0,input.size());
		byte[] byteOfKey = keyStr.getBytes(StandardCharsets.UTF_8);
		
		for (int i = 0; i < input.size()/2; i++) {
			BitSet bitsetKey = BitSet.valueOf(new byte[] { byteOfKey[i] });
			
			BitSet bits = new BitSet();
			bits = commonOperation.intToBitSet(input.get(i));
			bits.xor(bitsetKey);
			input.set(i, commonOperation.bitSetToInt(bits));
		}
		for (int i = 0; i < input.size()/2; i++) {
			result.set(i, input.get(input.size()/2 + i ));
			result.set(input.size()/2 + i, input.get(i));
		}
		return result;

	}
	

	public static ArrayList<Integer> feistelDec(String key, ArrayList<Integer> input){
		ArrayList<Integer> result= new ArrayList<Integer>();
		result = (ArrayList<Integer>) input.clone();

		if (input.size() == 1)
			return input;
		
		for (int i = 0; i < input.size()/2; i++) {
			result.set(i, input.get(input.size()/2 + i ));
			result.set(input.size()/2 + i, input.get(i));
		}
		
		/*Doing XOR the left side*/
		/*Prepare the key that match the length of the block*/
		String keyStr = key.substring(0,input.size());
		byte[] byteOfKey = keyStr.getBytes(StandardCharsets.UTF_8);
		
		for (int i = 0; i < input.size()/2; i++) {
			BitSet bitsetKey = BitSet.valueOf(new byte[] { byteOfKey[i] });
			
			BitSet bits = new BitSet();
			bits = commonOperation.intToBitSet(result.get(i));
			bits.xor(bitsetKey);
			result.set(i, commonOperation.bitSetToInt(bits));
		}
		return result;
	}
	
	public static ArrayList<Integer> shiftRowOddPerBlock(ArrayList<Integer> input){
		ArrayList<Integer> result= new ArrayList<Integer>();
		result = (ArrayList<Integer>) input.clone();
		/*Swap the odd row*/
		result.set(0, input.get(8));
		result.set(1, input.get(9));
		result.set(2, input.get(10));
		result.set(3, input.get(11));

		result.set(8, input.get(0));
		result.set(9, input.get(1));
		result.set(10, input.get(2));
		result.set(11, input.get(3));
		
		return result;
	}
	

	public static ArrayList<Integer> shiftRowEvenPerBlock(ArrayList<Integer> input){
		ArrayList<Integer> result= new ArrayList<Integer>();
		result = (ArrayList<Integer>) input.clone();
		/*Swap the even row*/
		result.set(4, input.get(12));
		result.set(5, input.get(13));
		result.set(6, input.get(14));
		result.set(7, input.get(15));

		result.set(12, input.get(4));
		result.set(13, input.get(5));
		result.set(14, input.get(6));
		result.set(15, input.get(7));
		
		return result;
	}
	
	public static ArrayList<Integer> mixColumnEncPerBlock(ArrayList<Integer> input){
		ArrayList<Integer> result= new ArrayList<Integer>();
		/*Mix the column*/
		result.add(input.get(3));
		result.add(input.get(0));
		result.add(input.get(1));
		result.add(input.get(2));
		result.add(input.get(6));
		result.add(input.get(7));
		result.add(input.get(4));
		result.add(input.get(5));
		result.add(input.get(9));
		result.add(input.get(10));
		result.add(input.get(11));
		result.add(input.get(8));
		result.add(input.get(15));
		result.add(input.get(14));
		result.add(input.get(13));
		result.add(input.get(12));
		return result;
	}
	
	public static ArrayList<Integer> mixColumnDecPerBlock(ArrayList<Integer> input){
		ArrayList<Integer> result= new ArrayList<Integer>();
		/*Mix the column*/
		result.add(input.get(1));
		result.add(input.get(2));
		result.add(input.get(3));
		result.add(input.get(0));
		result.add(input.get(6));
		result.add(input.get(7));
		result.add(input.get(4));
		result.add(input.get(5));
		result.add(input.get(11));
		result.add(input.get(8));
		result.add(input.get(9));
		result.add(input.get(10));
		result.add(input.get(15));
		result.add(input.get(14));
		result.add(input.get(13));
		result.add(input.get(12));
		return result;
	}
}


