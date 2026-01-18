export interface ConversionResult {
  success: boolean;
  value?: string | number;
  error?: string;
}

export class BaseConverter {
  private static readonly MAX_BASE = 36;
  private static readonly MIN_BASE = 2;

  static convert(value: string | number, fromBase: number, toBase: number): ConversionResult {
    try {
      if (!this.isValidBase(fromBase) || !this.isValidBase(toBase)) {
        return {
          success: false,
          error: `Base must be between ${this.MIN_BASE} and ${this.MAX_BASE}`
        };
      }

      const stringValue = String(value).trim();
      if (!stringValue) {
        return {
          success: false,
          error: 'Value cannot be empty'
        };
      }

      if (!this.isValidForBase(stringValue, fromBase)) {
        return {
          success: false,
          error: `Invalid value for base ${fromBase}`
        };
      }

      const decimalValue = parseInt(stringValue, fromBase);
      if (isNaN(decimalValue)) {
        return {
          success: false,
          error: 'Failed to parse value'
        };
      }

      const result = decimalValue.toString(toBase);
      return {
        success: true,
        value: result
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown conversion error'
      };
    }
  }

  static toDecimal(value: string | number, fromBase: number): ConversionResult {
    return this.convert(value, fromBase, 10);
  }

  static fromDecimal(value: string | number, toBase: number): ConversionResult {
    return this.convert(value, 10, toBase);
  }

  static convertWithValidation(value: string, fromBase: number, toBase: number): ConversionResult {
    const trimmedValue = value.trim().toLowerCase();
    
    if (!this.isValidBase(fromBase) || !this.isValidBase(toBase)) {
      return {
        success: false,
        error: `Base must be between ${this.MIN_BASE} and ${this.MAX_BASE}`
      };
    }

    if (!this.isValidForBase(trimmedValue, fromBase)) {
      return {
        success: false,
        error: `Value contains invalid characters for base ${fromBase}`
      };
    }

    return this.convert(trimmedValue, fromBase, toBase);
  }

  static batch(values: (string | number)[], fromBase: number, toBase: number): ConversionResult[] {
    return values.map(value => this.convert(value, fromBase, toBase));
  }

  static getSupportedBases(): number[] {
    return Array.from({ length: this.MAX_BASE - this.MIN_BASE + 1 }, (_, i) => i + this.MIN_BASE);
  }

  static getCharacterSet(base: number): string[] {
    if (!this.isValidBase(base)) {
      throw new Error(`Invalid base: ${base}`);
    }

    const chars = '0123456789abcdefghijklmnopqrstuvwxyz';
    return chars.slice(0, base).split('');
  }

  static getMaxValue(base: number, digits: number): string {
    if (!this.isValidBase(base)) {
      throw new Error(`Invalid base: ${base}`);
    }

    const maxChar = this.getCharacterSet(base).slice(-1)[0];
    return maxChar.repeat(digits);
  }

  static padLeft(value: string, base: number, length: number, padChar?: string): string {
    const chars = this.getCharacterSet(base);
    const defaultPadChar = padChar || chars[0];
    
    if (!chars.includes(defaultPadChar)) {
      throw new Error(`Pad character '${defaultPadChar}' is not valid for base ${base}`);
    }

    return value.padStart(length, defaultPadChar);
  }

  static padRight(value: string, base: number, length: number, padChar?: string): string {
    const chars = this.getCharacterSet(base);
    const defaultPadChar = padChar || chars[0];
    
    if (!chars.includes(defaultPadChar)) {
      throw new Error(`Pad character '${defaultPadChar}' is not valid for base ${base}`);
    }

    return value.padEnd(length, defaultPadChar);
  }

  private static isValidBase(base: number): boolean {
    return Number.isInteger(base) && base >= this.MIN_BASE && base <= this.MAX_BASE;
  }

  private static isValidForBase(value: string, base: number): boolean {
    const validChars = this.getCharacterSet(base);
    const normalizedValue = value.toLowerCase();
    
    for (const char of normalizedValue) {
      if (!validChars.includes(char)) {
        return false;
      }
    }
    
    return true;
  }

  static compareValues(value1: string, value2: string, base: number): number {
    const result1 = this.toDecimal(value1, base);
    const result2 = this.toDecimal(value2, base);

    if (!result1.success || !result2.success) {
      throw new Error('Cannot compare invalid values');
    }

    const num1 = Number(result1.value);
    const num2 = Number(result2.value);

    return num1 - num2;
  }

  static add(value1: string, value2: string, base: number): ConversionResult {
    try {
      const result1 = this.toDecimal(value1, base);
      const result2 = this.toDecimal(value2, base);

      if (!result1.success) return result1;
      if (!result2.success) return result2;

      const sum = Number(result1.value) + Number(result2.value);
      return this.fromDecimal(sum, base);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Addition failed'
      };
    }
  }

  static subtract(value1: string, value2: string, base: number): ConversionResult {
    try {
      const result1 = this.toDecimal(value1, base);
      const result2 = this.toDecimal(value2, base);

      if (!result1.success) return result1;
      if (!result2.success) return result2;

      const difference = Number(result1.value) - Number(result2.value);
      return this.fromDecimal(difference, base);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Subtraction failed'
      };
    }
  }
}