import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.Random;

import javax.naming.spi.DirStateFactory.Result;


public class newAlgorithm {
	final static int  blockSize = 8;
	
	/*To encrypt*/
	public static ArrayList<Integer> blockE(String key, ArrayList<Integer> blockPlainText){
		/*To save the cipher text*/
		ArrayList<Integer> singleBlock = new ArrayList<Integer>();

		/*Prepare the substring of key that match the length of the block*/
		String keyStr = key.substring(0,blockPlainText.size());
		byte[] byteOfKey = keyStr.getBytes(StandardCharsets.UTF_8);
		BitSet bitsetKey = BitSet.valueOf(new byte[] { byteOfKey[0] });

		singleBlock = sBoxEnc(key, singleBlock);
		singleBlock = feistelEnc(key, blockPlainText);
		singleBlock = sBoxEnc(key, singleBlock);
		
		return singleBlock;
	}
	
	/*To decrypt*/
	public static ArrayList<Integer> blockD(String key, ArrayList<Integer> blockPlainText){
		/*To save the cipher text*/
		ArrayList<Integer> singleBlock = new ArrayList<Integer>();
		
		/*Prepare the key that match the length of the block*/
		String keyStr = key.substring(0,blockPlainText.size());
		byte[] byteOfKey = keyStr.getBytes(StandardCharsets.UTF_8);
		BitSet bitsetKey = BitSet.valueOf(new byte[] { byteOfKey[0] });		

		singleBlock = feistelDesc(key, singleBlock);
		singleBlock = sBoxDec(key, blockPlainText);
		singleBlock = feistelDesc(key, singleBlock);
		
		
		return singleBlock;
		
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
	

	public static ArrayList<Integer> feistelDesc(String key, ArrayList<Integer> input){
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
	
	
}


