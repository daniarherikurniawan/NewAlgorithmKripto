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
//		/*To save the cipher text*/
//		blockPlainText = commonOperation.shiftLeftPerByte(blockPlainText);
//		blockPlainText = feistelEnc(key, blockPlainText);
		System.out.println("a "+blockPlainText.toString());
		blockPlainText = sBoxEnc4to6(key, blockPlainText);

		System.out.println("b "+blockPlainText.toString());
//		blockPlainText = shiftRowOddPerBlock(blockPlainText);
		blockPlainText = mixColumnEncPerBlock( blockPlainText);
		System.out.println("c "+blockPlainText.toString());
////		blockPlainText = shiftRowEvenPerBlock( blockPlainText);
////		System.out.println("c "+blockPlainText.toString());
//		
		blockPlainText = sBoxEnc6to4(key, blockPlainText);
		System.out.println("d "+blockPlainText.toString());
//		System.out.println(blockPlainText.toString());
//		blockPlainText = feistelEnc(key, blockPlainText);
//		blockPlainText = commonOperation.shiftLeftPerByte(blockPlainText);
//		
		return blockPlainText;
	}
	
	/*To decrypt*/
	public static ArrayList<Integer> blockD(String key, ArrayList<Integer> blockPlainText){
		/*To save the cipher text*/
//		blockPlainText = commonOperation.shiftRightPerByte(blockPlainText);
//		blockPlainText = feistelDec(key, blockPlainText);
		System.out.println("a "+blockPlainText.toString());
		blockPlainText = sBoxEnc4to6(key, blockPlainText);

		System.out.println("b "+blockPlainText.toString());
//		blockPlainText = shiftRowEvenPerBlock( blockPlainText);
		blockPlainText = mixColumnDecPerBlock( blockPlainText);
//		blockPlainText = shiftRowOddPerBlock(blockPlainText);

		System.out.println("c "+blockPlainText.toString());
		blockPlainText = sBoxEnc6to4(key, blockPlainText);
//		blockPlainText = feistelDec(key, blockPlainText);
//		blockPlainText = commonOperation.shiftRightPerByte(blockPlainText);
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
	public static ArrayList<Integer> sBoxEnc4to6(String key, ArrayList<Integer> blockPlainText){
		/*To save the result*/
		ArrayList<Integer> result = new ArrayList<Integer>();

		for (int i = 0 ; i < blockPlainText.size() ; i += 4){
			BitSet rowByte = new BitSet();
			
			/*Prepare xor result for padding*/
			BitSet xorResult = new BitSet();
			
			/*Operation happens per 4 Byte*/
			for (int j = 0; j < 4; j++) {
				BitSet bits = commonOperation.intToBitSet(blockPlainText.get(i+j));
				
				/*Combine byte of one row => total 32 bits*/
				for (int k = bits.nextSetBit(0); k >= 0 ; k =bits.nextSetBit(k + 1)){
					rowByte.set((j*8)+k);
				}				
				
				/*Compute xor per two bitset*/
				if(j == 0 || j == 2){
					BitSet currResult = commonOperation.intToBitSet(blockPlainText.get(i+j+1));
					currResult.xor(bits);
					for (int l = currResult.nextSetBit(j); l < j+5 && l != -1; l = currResult.nextSetBit(l+1)) {
						xorResult.set(((j/2)*8)+l); 
					}
				}
			}
			
			/*add last two bits to the xor result to make it 18 bits*/
			for (int j = rowByte.nextSetBit(30); j < 32 && j != -1; j = rowByte.nextSetBit(j+1) ) {
				xorResult.set(j%2 + 16);
			}

//			System.out.println("result "+rowByte);
//			System.out.println("xorResult "+xorResult.toString());
			
			/*Break per 5 bits and add 3 bits in the last from xorResult*/
			int idx = 0;
			for (int j = 0; j < 30; j+= 5) {
				BitSet newByte = new BitSet();
				for (int k = rowByte.nextSetBit(j); k < j+5 && k != -1; k = rowByte.nextSetBit(k+1)) {
					 newByte.set(k%5); 
				}
				
				/*add 3 bits from xor result*/
				for (int k = xorResult.nextSetBit(idx); k < idx+3 && k != -1; k = xorResult.nextSetBit(k + 1)) {
					newByte.set(k%3 + 5);
				}
				
				idx += 3;
				
//				System.out.println("newByte :"+newByte.toString());
				
				/*After binary operation, it will be converted to integer*/
				result.add(commonOperation.bitSetToInt(newByte));
			}
//			System.out.println();
		}
		
		return result;
	}
	
	/*S Box for Encryption*/
	public static ArrayList<Integer> sBoxEnc6to4(String key, ArrayList<Integer> blockPlainText){
		/*To save the result*/
		ArrayList<Integer> result = new ArrayList<Integer>();
		for (int i = 0 ; i < blockPlainText.size() ; i += 6){
			BitSet rowByte = new BitSet();
			
			
			/*Operation happens per 6 Byte*/
			for (int j = 0; j < 6; j++) {
				BitSet bits = commonOperation.intToBitSet(blockPlainText.get(i+j));
				
				/*remove last 3 bits*/
				for (int k = bits.nextSetBit(5); k >= 0 ; k =bits.nextSetBit(k + 1)){
					bits.clear(k);
				}		
				/*Combine byte of one row => total 32 bits*/
				for (int k = bits.nextSetBit(0); k >= 0 ; k =bits.nextSetBit(k + 1)){
					rowByte.set((j*5)+k);
				}				
			}
			
			/*append the last two bits from the last element in a row*/
			BitSet lastByte = commonOperation.intToBitSet(blockPlainText.get(i+5));
			for (int k = lastByte.nextSetBit(6); k >= 0 ; k =lastByte.nextSetBit(k + 1)){
				rowByte.set(k%2 + 30);
			}		

//			System.out.println("rowByte :"+rowByte.toString());
			/*Split  per 8 bit or one Byte*/
			for (int j = 0; j < 32; j += 8) {
				BitSet bits = new BitSet();
				/*Combine byte of one row => total 32 bits*/
				for (int k = rowByte.nextSetBit(j); k < j+8 && k >= 0 ; k = rowByte.nextSetBit(k + 1)){
					bits.set(k%8);
				}				
//				System.out.println("bits :"+bits.toString());
				
				/*After binary operation, it will be converted to integer*/
				result.add(commonOperation.bitSetToInt(bits));
				
			}
			
//			System.out.println();
		}
		return result;
	}
	
	/*Reverse the Byte*/
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
		for (int i = 0; i < 4; i++) {
			int j;
			for (j = 0; j < i+1; j++) {
				result.add(input.get((i + 1) *5 + j));
			}
			for (int k = 0; k < 6 - j; k++) {
				result.add(input.get(k + (i*6) ));
			}
		}
		return result;
	}
	
	public static ArrayList<Integer> mixColumnDecPerBlock(ArrayList<Integer> input){
		ArrayList<Integer> result= new ArrayList<Integer>();
		/*Mix the column*/
//		System.out.println("return "+input);
		for (int i = 0; i < 4; i++) {
			int j;
			for (j = 0; j < (5 - i); j++) {
//				System.out.println(j);
				result.add(input.get(j+1 + (i*6+i)));
			}
			for (int k = 0; k < 6 - j; k++) {
				result.add(input.get(i * 6 + k));
			}
		}
//		System.out.println("return "+result);
		return result;
	}
}


