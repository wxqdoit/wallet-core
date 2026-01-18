import { ConversionResult } from './converter';

export class HexConverter {
  static toHex(value: string | number, fromBase: number = 10): ConversionResult {
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
        value: decimalValue.toString(16).toLowerCase()
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Hex conversion failed'
      };
    }
  }

  static fromHex(hexValue: string, toBase: number = 10): ConversionResult {
    try {
      const cleanHex = this.cleanHex(hexValue);
      if (!this.isValidHex(cleanHex)) {
        return {
          success: false,
          error: 'Invalid hexadecimal string'
        };
      }

      const decimalValue = parseInt(cleanHex, 16);
      const result = toBase === 10 ? decimalValue : decimalValue.toString(toBase);

      return {
        success: true,
        value: result
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Hex conversion failed'
      };
    }
  }

  static isValidHex(value: string): boolean {
    return /^[0-9a-fA-F]+$/.test(value.trim());
  }

  static cleanHex(hexValue: string): string {
    return hexValue.trim().toLowerCase().replace(/^0x/, '').replace(/^#/, '');
  }

  static normalize(hexValue: string, options: {
    uppercase?: boolean;
    prefix?: string;
    padding?: number;
  } = {}): string {
    const {
      uppercase = false,
      prefix = '',
      padding = 0
    } = options;

    let cleaned = this.cleanHex(hexValue);
    
    if (padding > 0) {
      cleaned = cleaned.padStart(padding, '0');
    }

    const result = uppercase ? cleaned.toUpperCase() : cleaned.toLowerCase();
    return prefix + result;
  }

  static format(hexValue: string, options: {
    uppercase?: boolean;
    prefix?: string;
    groupSize?: number;
    separator?: string;
    padding?: number;
  } = {}): string {
    const {
      uppercase = false,
      prefix = '0x',
      groupSize = 0,
      separator = ' ',
      padding = 0
    } = options;

    let cleaned = this.cleanHex(hexValue);
    
    if (padding > 0) {
      cleaned = cleaned.padStart(padding, '0');
    }

    const formatted = uppercase ? cleaned.toUpperCase() : cleaned.toLowerCase();

    if (groupSize > 0) {
      const groups = [];
      for (let i = 0; i < formatted.length; i += groupSize) {
        groups.push(formatted.slice(i, i + groupSize));
      }
      return prefix + groups.join(separator);
    }

    return prefix + formatted;
  }

  static pad(hexValue: string, length: number): string {
    const cleaned = this.cleanHex(hexValue);
    return cleaned.padStart(length, '0');
  }

  static padToBytes(hexValue: string): string {
    const cleaned = this.cleanHex(hexValue);
    const remainder = cleaned.length % 2;
    return remainder === 0 ? cleaned : this.pad(cleaned, cleaned.length + 1);
  }

  static split(hexValue: string, groupSize: number = 2): string[] {
    const cleaned = this.cleanHex(hexValue);
    const paddedValue = this.pad(cleaned, Math.ceil(cleaned.length / groupSize) * groupSize);
    const groups = [];
    
    for (let i = 0; i < paddedValue.length; i += groupSize) {
      groups.push(paddedValue.slice(i, i + groupSize));
    }
    
    return groups;
  }

  static reverse(hexValue: string): string {
    const cleaned = this.cleanHex(hexValue);
    const bytes = this.split(cleaned, 2);
    return bytes.reverse().join('');
  }

  static swapEndian(hexValue: string): string {
    return this.reverse(hexValue);
  }

  static add(hex1: string, hex2: string): ConversionResult {
    try {
      const cleaned1 = this.cleanHex(hex1);
      const cleaned2 = this.cleanHex(hex2);

      if (!this.isValidHex(cleaned1) || !this.isValidHex(cleaned2)) {
        return {
          success: false,
          error: 'Invalid hexadecimal values'
        };
      }

      const decimal1 = parseInt(cleaned1, 16);
      const decimal2 = parseInt(cleaned2, 16);
      const sum = decimal1 + decimal2;

      return {
        success: true,
        value: sum.toString(16).toLowerCase()
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Hex addition failed'
      };
    }
  }

  static subtract(hex1: string, hex2: string): ConversionResult {
    try {
      const cleaned1 = this.cleanHex(hex1);
      const cleaned2 = this.cleanHex(hex2);

      if (!this.isValidHex(cleaned1) || !this.isValidHex(cleaned2)) {
        return {
          success: false,
          error: 'Invalid hexadecimal values'
        };
      }

      const decimal1 = parseInt(cleaned1, 16);
      const decimal2 = parseInt(cleaned2, 16);
      const difference = decimal1 - decimal2;

      return {
        success: true,
        value: difference.toString(16).toLowerCase()
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Hex subtraction failed'
      };
    }
  }

  static and(hex1: string, hex2: string): ConversionResult {
    try {
      const cleaned1 = this.cleanHex(hex1);
      const cleaned2 = this.cleanHex(hex2);

      if (!this.isValidHex(cleaned1) || !this.isValidHex(cleaned2)) {
        return {
          success: false,
          error: 'Invalid hexadecimal values'
        };
      }

      const decimal1 = parseInt(cleaned1, 16);
      const decimal2 = parseInt(cleaned2, 16);
      const result = decimal1 & decimal2;

      return {
        success: true,
        value: result.toString(16).toLowerCase()
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Hex AND failed'
      };
    }
  }

  static or(hex1: string, hex2: string): ConversionResult {
    try {
      const cleaned1 = this.cleanHex(hex1);
      const cleaned2 = this.cleanHex(hex2);

      if (!this.isValidHex(cleaned1) || !this.isValidHex(cleaned2)) {
        return {
          success: false,
          error: 'Invalid hexadecimal values'
        };
      }

      const decimal1 = parseInt(cleaned1, 16);
      const decimal2 = parseInt(cleaned2, 16);
      const result = decimal1 | decimal2;

      return {
        success: true,
        value: result.toString(16).toLowerCase()
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Hex OR failed'
      };
    }
  }

  static xor(hex1: string, hex2: string): ConversionResult {
    try {
      const cleaned1 = this.cleanHex(hex1);
      const cleaned2 = this.cleanHex(hex2);

      if (!this.isValidHex(cleaned1) || !this.isValidHex(cleaned2)) {
        return {
          success: false,
          error: 'Invalid hexadecimal values'
        };
      }

      const decimal1 = parseInt(cleaned1, 16);
      const decimal2 = parseInt(cleaned2, 16);
      const result = decimal1 ^ decimal2;

      return {
        success: true,
        value: result.toString(16).toLowerCase()
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Hex XOR failed'
      };
    }
  }

  static complement(hexValue: string): ConversionResult {
    try {
      const cleaned = this.cleanHex(hexValue);
      if (!this.isValidHex(cleaned)) {
        return {
          success: false,
          error: 'Invalid hexadecimal value'
        };
      }

      const decimal = parseInt(cleaned, 16);
      const bitLength = cleaned.length * 4;
      const mask = (1 << bitLength) - 1;
      const result = (~decimal & mask);

      return {
        success: true,
        value: result.toString(16).toLowerCase().padStart(cleaned.length, '0')
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Hex complement failed'
      };
    }
  }

  static toBytes(hexValue: string): number[] {
    const cleaned = this.cleanHex(hexValue);
    const paddedHex = this.padToBytes(cleaned);
    const bytes = [];

    for (let i = 0; i < paddedHex.length; i += 2) {
      bytes.push(parseInt(paddedHex.slice(i, i + 2), 16));
    }

    return bytes;
  }

  static fromBytes(bytes: number[]): ConversionResult {
    try {
      const hexBytes = bytes.map(byte => {
        if (byte < 0 || byte > 255) {
          throw new Error(`Invalid byte value: ${byte}`);
        }
        return byte.toString(16).padStart(2, '0');
      });

      return {
        success: true,
        value: hexBytes.join('').toLowerCase()
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Bytes to hex conversion failed'
      };
    }
  }

  static compare(hex1: string, hex2: string): number {
    const cleaned1 = this.cleanHex(hex1);
    const cleaned2 = this.cleanHex(hex2);
    
    const decimal1 = parseInt(cleaned1, 16);
    const decimal2 = parseInt(cleaned2, 16);
    
    return decimal1 - decimal2;
  }

  static isEqual(hex1: string, hex2: string): boolean {
    return this.compare(hex1, hex2) === 0;
  }

  static random(length: number): string {
    const chars = '0123456789abcdef';
    let result = '';
    
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    return result;
  }
}