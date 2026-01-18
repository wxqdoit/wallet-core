import { ConversionResult } from './converter';

export class OctalConverter {
  static toOctal(value: string | number, fromBase: number = 10): ConversionResult {
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
        value: decimalValue.toString(8)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Octal conversion failed'
      };
    }
  }

  static fromOctal(octalValue: string, toBase: number = 10): ConversionResult {
    try {
      const cleanOctal = this.cleanOctal(octalValue);
      if (!this.isValidOctal(cleanOctal)) {
        return {
          success: false,
          error: 'Invalid octal string'
        };
      }

      const decimalValue = parseInt(cleanOctal, 8);
      const result = toBase === 10 ? decimalValue : decimalValue.toString(toBase);

      return {
        success: true,
        value: result
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Octal conversion failed'
      };
    }
  }

  static isValidOctal(value: string): boolean {
    return /^[0-7]+$/.test(value.trim());
  }

  static cleanOctal(octalValue: string): string {
    return octalValue.trim().replace(/^0o/, '').replace(/^0/, '');
  }

  static normalize(octalValue: string, options: {
    prefix?: string;
    padding?: number;
  } = {}): string {
    const {
      prefix = '',
      padding = 0
    } = options;

    let cleaned = this.cleanOctal(octalValue);
    
    if (padding > 0) {
      cleaned = cleaned.padStart(padding, '0');
    }

    return prefix + cleaned;
  }

  static format(octalValue: string, options: {
    prefix?: string;
    groupSize?: number;
    separator?: string;
    padding?: number;
  } = {}): string {
    const {
      prefix = '0o',
      groupSize = 0,
      separator = ' ',
      padding = 0
    } = options;

    let cleaned = this.cleanOctal(octalValue);
    
    if (padding > 0) {
      cleaned = cleaned.padStart(padding, '0');
    }

    if (groupSize > 0) {
      const groups = [];
      for (let i = 0; i < cleaned.length; i += groupSize) {
        groups.push(cleaned.slice(i, i + groupSize));
      }
      return prefix + groups.join(separator);
    }

    return prefix + cleaned;
  }

  static pad(octalValue: string, length: number): string {
    const cleaned = this.cleanOctal(octalValue);
    return cleaned.padStart(length, '0');
  }

  static split(octalValue: string, groupSize: number = 3): string[] {
    const cleaned = this.cleanOctal(octalValue);
    const paddedValue = this.pad(cleaned, Math.ceil(cleaned.length / groupSize) * groupSize);
    const groups = [];
    
    for (let i = 0; i < paddedValue.length; i += groupSize) {
      groups.push(paddedValue.slice(i, i + groupSize));
    }
    
    return groups;
  }

  static add(octal1: string, octal2: string): ConversionResult {
    try {
      const cleaned1 = this.cleanOctal(octal1);
      const cleaned2 = this.cleanOctal(octal2);

      if (!this.isValidOctal(cleaned1) || !this.isValidOctal(cleaned2)) {
        return {
          success: false,
          error: 'Invalid octal values'
        };
      }

      const decimal1 = parseInt(cleaned1, 8);
      const decimal2 = parseInt(cleaned2, 8);
      const sum = decimal1 + decimal2;

      return {
        success: true,
        value: sum.toString(8)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Octal addition failed'
      };
    }
  }

  static subtract(octal1: string, octal2: string): ConversionResult {
    try {
      const cleaned1 = this.cleanOctal(octal1);
      const cleaned2 = this.cleanOctal(octal2);

      if (!this.isValidOctal(cleaned1) || !this.isValidOctal(cleaned2)) {
        return {
          success: false,
          error: 'Invalid octal values'
        };
      }

      const decimal1 = parseInt(cleaned1, 8);
      const decimal2 = parseInt(cleaned2, 8);
      const difference = decimal1 - decimal2;

      return {
        success: true,
        value: difference.toString(8)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Octal subtraction failed'
      };
    }
  }

  static multiply(octal1: string, octal2: string): ConversionResult {
    try {
      const cleaned1 = this.cleanOctal(octal1);
      const cleaned2 = this.cleanOctal(octal2);

      if (!this.isValidOctal(cleaned1) || !this.isValidOctal(cleaned2)) {
        return {
          success: false,
          error: 'Invalid octal values'
        };
      }

      const decimal1 = parseInt(cleaned1, 8);
      const decimal2 = parseInt(cleaned2, 8);
      const product = decimal1 * decimal2;

      return {
        success: true,
        value: product.toString(8)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Octal multiplication failed'
      };
    }
  }

  static divide(octal1: string, octal2: string): ConversionResult {
    try {
      const cleaned1 = this.cleanOctal(octal1);
      const cleaned2 = this.cleanOctal(octal2);

      if (!this.isValidOctal(cleaned1) || !this.isValidOctal(cleaned2)) {
        return {
          success: false,
          error: 'Invalid octal values'
        };
      }

      const decimal1 = parseInt(cleaned1, 8);
      const decimal2 = parseInt(cleaned2, 8);

      if (decimal2 === 0) {
        return {
          success: false,
          error: 'Division by zero'
        };
      }

      const quotient = Math.floor(decimal1 / decimal2);

      return {
        success: true,
        value: quotient.toString(8)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Octal division failed'
      };
    }
  }

  static modulo(octal1: string, octal2: string): ConversionResult {
    try {
      const cleaned1 = this.cleanOctal(octal1);
      const cleaned2 = this.cleanOctal(octal2);

      if (!this.isValidOctal(cleaned1) || !this.isValidOctal(cleaned2)) {
        return {
          success: false,
          error: 'Invalid octal values'
        };
      }

      const decimal1 = parseInt(cleaned1, 8);
      const decimal2 = parseInt(cleaned2, 8);

      if (decimal2 === 0) {
        return {
          success: false,
          error: 'Modulo by zero'
        };
      }

      const remainder = decimal1 % decimal2;

      return {
        success: true,
        value: remainder.toString(8)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Octal modulo failed'
      };
    }
  }

  static compare(octal1: string, octal2: string): number {
    const cleaned1 = this.cleanOctal(octal1);
    const cleaned2 = this.cleanOctal(octal2);
    
    const decimal1 = parseInt(cleaned1, 8);
    const decimal2 = parseInt(cleaned2, 8);
    
    return decimal1 - decimal2;
  }

  static isEqual(octal1: string, octal2: string): boolean {
    return this.compare(octal1, octal2) === 0;
  }

  static isGreater(octal1: string, octal2: string): boolean {
    return this.compare(octal1, octal2) > 0;
  }

  static isLess(octal1: string, octal2: string): boolean {
    return this.compare(octal1, octal2) < 0;
  }

  static min(octalValues: string[]): ConversionResult {
    try {
      if (octalValues.length === 0) {
        return {
          success: false,
          error: 'Array cannot be empty'
        };
      }

      let minValue = octalValues[0];
      for (let i = 1; i < octalValues.length; i++) {
        if (this.isLess(octalValues[i], minValue)) {
          minValue = octalValues[i];
        }
      }

      return {
        success: true,
        value: this.cleanOctal(minValue)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Min calculation failed'
      };
    }
  }

  static max(octalValues: string[]): ConversionResult {
    try {
      if (octalValues.length === 0) {
        return {
          success: false,
          error: 'Array cannot be empty'
        };
      }

      let maxValue = octalValues[0];
      for (let i = 1; i < octalValues.length; i++) {
        if (this.isGreater(octalValues[i], maxValue)) {
          maxValue = octalValues[i];
        }
      }

      return {
        success: true,
        value: this.cleanOctal(maxValue)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Max calculation failed'
      };
    }
  }

  static sum(octalValues: string[]): ConversionResult {
    try {
      if (octalValues.length === 0) {
        return {
          success: false,
          error: 'Array cannot be empty'
        };
      }

      let total = 0;
      for (const octalValue of octalValues) {
        const cleaned = this.cleanOctal(octalValue);
        if (!this.isValidOctal(cleaned)) {
          return {
            success: false,
            error: `Invalid octal value: ${octalValue}`
          };
        }
        total += parseInt(cleaned, 8);
      }

      return {
        success: true,
        value: total.toString(8)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Sum calculation failed'
      };
    }
  }

  static average(octalValues: string[]): ConversionResult {
    try {
      const sumResult = this.sum(octalValues);
      if (!sumResult.success) {
        return sumResult;
      }

      const sumDecimal = parseInt(String(sumResult.value), 8);
      const average = Math.floor(sumDecimal / octalValues.length);

      return {
        success: true,
        value: average.toString(8)
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Average calculation failed'
      };
    }
  }

  static increment(octalValue: string): ConversionResult {
    return this.add(octalValue, '1');
  }

  static decrement(octalValue: string): ConversionResult {
    return this.subtract(octalValue, '1');
  }

  static random(length: number): string {
    const chars = '01234567';
    let result = '';
    
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    return result;
  }
}