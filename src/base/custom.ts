import { ConversionResult } from './converter';

export interface CustomBaseOptions {
  alphabet: string;
  caseSensitive?: boolean;
  padding?: {
    char: string;
    length: number;
  };
}

export class CustomBaseConverter {
  static convert(value: string, fromOptions: CustomBaseOptions, toOptions: CustomBaseOptions): ConversionResult {
    try {
      const decimalResult = this.toDecimal(value, fromOptions);
      if (!decimalResult.success) {
        return decimalResult;
      }

      return this.fromDecimal(Number(decimalResult.value), toOptions);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Custom base conversion failed'
      };
    }
  }

  static toDecimal(value: string, options: CustomBaseOptions): ConversionResult {
    try {
      const { alphabet, caseSensitive = true } = options;
      
      if (!this.isValidAlphabet(alphabet)) {
        return {
          success: false,
          error: 'Invalid alphabet: must contain unique characters'
        };
      }

      const processedValue = caseSensitive ? value : value.toLowerCase();
      const processedAlphabet = caseSensitive ? alphabet : alphabet.toLowerCase();
      const base = alphabet.length;

      if (!this.isValidForCustomBase(processedValue, processedAlphabet)) {
        return {
          success: false,
          error: `Invalid value for custom base with alphabet: ${alphabet}`
        };
      }

      let result = 0;
      let power = 0;

      for (let i = processedValue.length - 1; i >= 0; i--) {
        const char = processedValue[i];
        const digitValue = processedAlphabet.indexOf(char);
        result += digitValue * Math.pow(base, power);
        power++;
      }

      return {
        success: true,
        value: result
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Decimal conversion failed'
      };
    }
  }

  static fromDecimal(decimal: number, options: CustomBaseOptions): ConversionResult {
    try {
      const { alphabet, padding } = options;
      
      if (!this.isValidAlphabet(alphabet)) {
        return {
          success: false,
          error: 'Invalid alphabet: must contain unique characters'
        };
      }

      if (decimal < 0) {
        return {
          success: false,
          error: 'Negative numbers not supported'
        };
      }

      if (!Number.isInteger(decimal)) {
        return {
          success: false,
          error: 'Only integers are supported'
        };
      }

      const base = alphabet.length;
      let result = '';
      let num = decimal;

      if (num === 0) {
        result = alphabet[0];
      } else {
        while (num > 0) {
          result = alphabet[num % base] + result;
          num = Math.floor(num / base);
        }
      }

      if (padding && result.length < padding.length) {
        result = result.padStart(padding.length, padding.char);
      }

      return {
        success: true,
        value: result
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'From decimal conversion failed'
      };
    }
  }

  static createBase(characters: string): CustomBaseOptions {
    return {
      alphabet: characters,
      caseSensitive: true
    };
  }

  static createBase58(): CustomBaseOptions {
    return {
      alphabet: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
      caseSensitive: true
    };
  }

  static createBase32(): CustomBaseOptions {
    return {
      alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
      caseSensitive: false
    };
  }

  static createBase32Hex(): CustomBaseOptions {
    return {
      alphabet: '0123456789ABCDEFGHIJKLMNOPQRSTUV',
      caseSensitive: false
    };
  }

  static createBase36(): CustomBaseOptions {
    return {
      alphabet: '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      caseSensitive: false
    };
  }

  static createBase62(): CustomBaseOptions {
    return {
      alphabet: '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
      caseSensitive: true
    };
  }

  static createDnaBase(): CustomBaseOptions {
    return {
      alphabet: 'ATCG',
      caseSensitive: false
    };
  }

  static createBraille(): CustomBaseOptions {
    return {
      alphabet: '⠀⠁⠂⠃⠄⠅⠆⠇⠈⠉⠊⠋⠌⠍⠎⠏⠐⠑⠒⠓⠔⠕⠖⠗⠘⠙⠚⠛⠜⠝⠞⠟⠠⠡⠢⠣⠤⠥⠦⠧⠨⠩⠪⠫⠬⠭⠮⠯⠰⠱⠲⠳⠴⠵⠶⠷⠸⠹⠺⠻⠼⠽⠾⠿',
      caseSensitive: true
    };
  }

  static encode58(data: string): ConversionResult {
    const base58 = this.createBase58();
    const bytes = Array.from(data).map(char => char.charCodeAt(0));
    
    let decimal = 0;
    for (const byte of bytes) {
      decimal = decimal * 256 + byte;
    }

    return this.fromDecimal(decimal, base58);
  }

  static decode58(encoded: string): ConversionResult {
    try {
      const base58 = this.createBase58();
      const decimalResult = this.toDecimal(encoded, base58);
      
      if (!decimalResult.success) {
        return decimalResult;
      }

      let num = Number(decimalResult.value);
      const bytes = [];
      
      while (num > 0) {
        bytes.unshift(num % 256);
        num = Math.floor(num / 256);
      }

      const result = String.fromCharCode(...bytes);
      return {
        success: true,
        value: result
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Base58 decoding failed'
      };
    }
  }

  static validateAlphabet(alphabet: string): {
    valid: boolean;
    issues: string[];
  } {
    const issues = [];
    
    if (alphabet.length < 2) {
      issues.push('Alphabet must contain at least 2 characters');
    }

    const uniqueChars = new Set(alphabet);
    if (uniqueChars.size !== alphabet.length) {
      issues.push('Alphabet must contain unique characters');
    }

    const controlChars = alphabet.match(/[\x00-\x1F\x7F]/g);
    if (controlChars) {
      issues.push('Alphabet contains control characters');
    }

    const whitespace = alphabet.match(/\s/g);
    if (whitespace) {
      issues.push('Alphabet contains whitespace characters');
    }

    return {
      valid: issues.length === 0,
      issues
    };
  }

  static getMaxValue(options: CustomBaseOptions, digits: number): string {
    const { alphabet } = options;
    const maxChar = alphabet[alphabet.length - 1];
    return maxChar.repeat(digits);
  }

  static compare(value1: string, value2: string, options: CustomBaseOptions): number {
    const decimal1Result = this.toDecimal(value1, options);
    const decimal2Result = this.toDecimal(value2, options);

    if (!decimal1Result.success || !decimal2Result.success) {
      throw new Error('Cannot compare invalid values');
    }

    return Number(decimal1Result.value) - Number(decimal2Result.value);
  }

  static add(value1: string, value2: string, options: CustomBaseOptions): ConversionResult {
    try {
      const decimal1Result = this.toDecimal(value1, options);
      const decimal2Result = this.toDecimal(value2, options);

      if (!decimal1Result.success) return decimal1Result;
      if (!decimal2Result.success) return decimal2Result;

      const sum = Number(decimal1Result.value) + Number(decimal2Result.value);
      return this.fromDecimal(sum, options);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Custom base addition failed'
      };
    }
  }

  static subtract(value1: string, value2: string, options: CustomBaseOptions): ConversionResult {
    try {
      const decimal1Result = this.toDecimal(value1, options);
      const decimal2Result = this.toDecimal(value2, options);

      if (!decimal1Result.success) return decimal1Result;
      if (!decimal2Result.success) return decimal2Result;

      const difference = Number(decimal1Result.value) - Number(decimal2Result.value);
      return this.fromDecimal(difference, options);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Custom base subtraction failed'
      };
    }
  }

  private static isValidAlphabet(alphabet: string): boolean {
    const uniqueChars = new Set(alphabet);
    return uniqueChars.size === alphabet.length && alphabet.length >= 2;
  }

  private static isValidForCustomBase(value: string, alphabet: string): boolean {
    for (const char of value) {
      if (!alphabet.includes(char)) {
        return false;
      }
    }
    return true;
  }

  static generateRandomValue(options: CustomBaseOptions, length: number): string {
    const { alphabet } = options;
    let result = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * alphabet.length);
      result += alphabet[randomIndex];
    }
    
    return result;
  }

  static getCharacterFrequency(value: string, options: CustomBaseOptions): Map<string, number> {
    const { alphabet } = options;
    const frequency = new Map<string, number>();
    
    alphabet.split('').forEach(char => frequency.set(char, 0));
    
    for (const char of value) {
      if (alphabet.includes(char)) {
        frequency.set(char, (frequency.get(char) || 0) + 1);
      }
    }
    
    return frequency;
  }

  static analyzeValue(value: string, options: CustomBaseOptions): {
    length: number;
    uniqueChars: number;
    frequency: Map<string, number>;
    isValid: boolean;
    decimal: number | null;
  } {
    const { alphabet } = options;
    const frequency = this.getCharacterFrequency(value, options);
    const uniqueChars = new Set(value).size;
    const isValid = this.isValidForCustomBase(value, alphabet);
    
    let decimal = null;
    if (isValid) {
      const decimalResult = this.toDecimal(value, options);
      if (decimalResult.success) {
        decimal = Number(decimalResult.value);
      }
    }

    return {
      length: value.length,
      uniqueChars,
      frequency,
      isValid,
      decimal
    };
  }
}