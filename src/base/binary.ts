import { ConversionResult } from './converter';

export class BinaryConverter {
  static toBinary(value: string | number, fromBase: number = 10): ConversionResult {
    try {
      const stringValue = String(value).trim();
      if (!stringValue) {
        return {
          success: false,
          error: 'Value cannot be empty'
        };
      }

      const decimalValue = fromBase === 10 ? Number(stringValue) : parseInt(stringValue, fromBase);
      if (isNaN(decimalValue)) {
        return {
          success: false,
          error: 'Invalid numeric value'
        };
      }

      return {
        success: true,
        value: decimalValue.toString(2)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Binary conversion failed'
      };
    }
  }

  static fromBinary(binaryValue: string, toBase: number = 10): ConversionResult {
    try {
      const cleanBinary = binaryValue.trim();
      if (!this.isValidBinary(cleanBinary)) {
        return {
          success: false,
          error: 'Invalid binary string'
        };
      }

      const decimalValue = parseInt(cleanBinary, 2);
      const result = toBase === 10 ? decimalValue : decimalValue.toString(toBase);

      return {
        success: true,
        value: result
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Binary conversion failed'
      };
    }
  }

  static isValidBinary(value: string): boolean {
    return /^[01]+$/.test(value.trim());
  }

  static pad(binaryValue: string, length: number): string {
    return binaryValue.padStart(length, '0');
  }

  static padToBytes(binaryValue: string): string {
    const remainder = binaryValue.length % 8;
    return remainder === 0 ? binaryValue : this.pad(binaryValue, binaryValue.length + (8 - remainder));
  }

  static padToNibbles(binaryValue: string): string {
    const remainder = binaryValue.length % 4;
    return remainder === 0 ? binaryValue : this.pad(binaryValue, binaryValue.length + (4 - remainder));
  }

  static split(binaryValue: string, groupSize: number = 4): string[] {
    const paddedValue = this.pad(binaryValue, Math.ceil(binaryValue.length / groupSize) * groupSize);
    const groups = [];
    
    for (let i = 0; i < paddedValue.length; i += groupSize) {
      groups.push(paddedValue.slice(i, i + groupSize));
    }
    
    return groups;
  }

  static format(binaryValue: string, options: {
    groupSize?: number;
    separator?: string;
    prefix?: string;
    suffix?: string;
  } = {}): string {
    const {
      groupSize = 4,
      separator = ' ',
      prefix = '',
      suffix = ''
    } = options;

    const groups = this.split(binaryValue, groupSize);
    return prefix + groups.join(separator) + suffix;
  }

  static reverse(binaryValue: string): string {
    return binaryValue.split('').reverse().join('');
  }

  static complement(binaryValue: string): string {
    return binaryValue.split('').map(bit => bit === '0' ? '1' : '0').join('');
  }

  static twosComplement(binaryValue: string): ConversionResult {
    try {
      const complemented = this.complement(binaryValue);
      const addResult = this.add(complemented, '1');
      
      if (!addResult.success) {
        return addResult;
      }

      return {
        success: true,
        value: String(addResult.value)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : "Two's complement failed"
      };
    }
  }

  static add(binary1: string, binary2: string): ConversionResult {
    try {
      if (!this.isValidBinary(binary1) || !this.isValidBinary(binary2)) {
        return {
          success: false,
          error: 'Invalid binary values'
        };
      }

      const decimal1 = parseInt(binary1, 2);
      const decimal2 = parseInt(binary2, 2);
      const sum = decimal1 + decimal2;

      return {
        success: true,
        value: sum.toString(2)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Binary addition failed'
      };
    }
  }

  static subtract(binary1: string, binary2: string): ConversionResult {
    try {
      if (!this.isValidBinary(binary1) || !this.isValidBinary(binary2)) {
        return {
          success: false,
          error: 'Invalid binary values'
        };
      }

      const decimal1 = parseInt(binary1, 2);
      const decimal2 = parseInt(binary2, 2);
      const difference = decimal1 - decimal2;

      return {
        success: true,
        value: difference.toString(2)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Binary subtraction failed'
      };
    }
  }

  static and(binary1: string, binary2: string): ConversionResult {
    try {
      if (!this.isValidBinary(binary1) || !this.isValidBinary(binary2)) {
        return {
          success: false,
          error: 'Invalid binary values'
        };
      }

      const decimal1 = parseInt(binary1, 2);
      const decimal2 = parseInt(binary2, 2);
      const result = decimal1 & decimal2;

      return {
        success: true,
        value: result.toString(2)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Binary AND failed'
      };
    }
  }

  static or(binary1: string, binary2: string): ConversionResult {
    try {
      if (!this.isValidBinary(binary1) || !this.isValidBinary(binary2)) {
        return {
          success: false,
          error: 'Invalid binary values'
        };
      }

      const decimal1 = parseInt(binary1, 2);
      const decimal2 = parseInt(binary2, 2);
      const result = decimal1 | decimal2;

      return {
        success: true,
        value: result.toString(2)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Binary OR failed'
      };
    }
  }

  static xor(binary1: string, binary2: string): ConversionResult {
    try {
      if (!this.isValidBinary(binary1) || !this.isValidBinary(binary2)) {
        return {
          success: false,
          error: 'Invalid binary values'
        };
      }

      const decimal1 = parseInt(binary1, 2);
      const decimal2 = parseInt(binary2, 2);
      const result = decimal1 ^ decimal2;

      return {
        success: true,
        value: result.toString(2)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Binary XOR failed'
      };
    }
  }

  static shiftLeft(binaryValue: string, positions: number): ConversionResult {
    try {
      if (!this.isValidBinary(binaryValue)) {
        return {
          success: false,
          error: 'Invalid binary value'
        };
      }

      const decimal = parseInt(binaryValue, 2);
      const result = decimal << positions;

      return {
        success: true,
        value: result.toString(2)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Binary left shift failed'
      };
    }
  }

  static shiftRight(binaryValue: string, positions: number): ConversionResult {
    try {
      if (!this.isValidBinary(binaryValue)) {
        return {
          success: false,
          error: 'Invalid binary value'
        };
      }

      const decimal = parseInt(binaryValue, 2);
      const result = decimal >> positions;

      return {
        success: true,
        value: result.toString(2)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Binary right shift failed'
      };
    }
  }

  static countOnes(binaryValue: string): number {
    return (binaryValue.match(/1/g) || []).length;
  }

  static countZeros(binaryValue: string): number {
    return (binaryValue.match(/0/g) || []).length;
  }

  static getWeight(binaryValue: string): number {
    return this.countOnes(binaryValue);
  }

  static isPowerOfTwo(binaryValue: string): boolean {
    if (!this.isValidBinary(binaryValue)) return false;
    return this.countOnes(binaryValue) === 1;
  }
}