export interface Base64Result {
  success: boolean;
  data?: string;
  error?: string;
}

export class Base64Converter {
  private static readonly BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  private static readonly BASE64_URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

  static encode(input: string, options: {
    urlSafe?: boolean;
    padding?: boolean;
  } = {}): Base64Result {
    try {
      const { urlSafe = false, padding = true } = options;
      
      if (typeof btoa !== 'undefined') {
        let result = btoa(input);
        
        if (urlSafe) {
          result = result.replace(/\+/g, '-').replace(/\//g, '_');
        }
        
        if (!padding) {
          result = result.replace(/=/g, '');
        }
        
        return {
          success: true,
          data: result
        };
      }

      return this.manualEncode(input, urlSafe, padding);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Base64 encoding failed'
      };
    }
  }

  static decode(input: string, options: {
    urlSafe?: boolean;
  } = {}): Base64Result {
    try {
      const { urlSafe = false } = options;
      let processedInput = input.trim();

      if (urlSafe) {
        processedInput = processedInput.replace(/-/g, '+').replace(/_/g, '/');
      }

      while (processedInput.length % 4 !== 0) {
        processedInput += '=';
      }

      if (!this.isValidBase64(processedInput)) {
        return {
          success: false,
          error: 'Invalid Base64 string'
        };
      }

      if (typeof atob !== 'undefined') {
        const result = atob(processedInput);
        return {
          success: true,
          data: result
        };
      }

      return this.manualDecode(processedInput);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Base64 decoding failed'
      };
    }
  }

  static encodeBytes(bytes: number[], options: {
    urlSafe?: boolean;
    padding?: boolean;
  } = {}): Base64Result {
    try {
      const string = String.fromCharCode(...bytes);
      return this.encode(string, options);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Bytes encoding failed'
      };
    }
  }

  static decodeToBytes(input: string, options: {
    urlSafe?: boolean;
  } = {}): { success: boolean; data?: number[]; error?: string } {
    try {
      const result = this.decode(input, options);
      if (!result.success) {
        return {
          success: false,
          error: result.error
        };
      }

      const bytes = [];
      for (let i = 0; i < result.data!.length; i++) {
        bytes.push(result.data!.charCodeAt(i));
      }

      return {
        success: true,
        data: bytes
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Bytes decoding failed'
      };
    }
  }

  static encodeUtf8(input: string, options: {
    urlSafe?: boolean;
    padding?: boolean;
  } = {}): Base64Result {
    try {
      const utf8Bytes = this.stringToUtf8Bytes(input);
      return this.encodeBytes(utf8Bytes, options);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'UTF-8 encoding failed'
      };
    }
  }

  static decodeUtf8(input: string, options: {
    urlSafe?: boolean;
  } = {}): Base64Result {
    try {
      const bytesResult = this.decodeToBytes(input, options);
      if (!bytesResult.success) {
        return {
          success: false,
          error: bytesResult.error
        };
      }

      const utf8String = this.utf8BytesToString(bytesResult.data!);
      return {
        success: true,
        data: utf8String
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'UTF-8 decoding failed'
      };
    }
  }

  static isValidBase64(input: string): boolean {
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    return base64Regex.test(input) && input.length % 4 === 0;
  }

  static isValidBase64Url(input: string): boolean {
    const base64UrlRegex = /^[A-Za-z0-9_-]*$/;
    return base64UrlRegex.test(input);
  }

  static format(input: string, options: {
    lineLength?: number;
    lineSeparator?: string;
  } = {}): string {
    const { lineLength = 76, lineSeparator = '\n' } = options;
    
    if (lineLength <= 0) return input;

    const lines = [];
    for (let i = 0; i < input.length; i += lineLength) {
      lines.push(input.slice(i, i + lineLength));
    }
    
    return lines.join(lineSeparator);
  }

  static removePadding(input: string): string {
    return input.replace(/=+$/, '');
  }

  static addPadding(input: string): string {
    while (input.length % 4 !== 0) {
      input += '=';
    }
    return input;
  }

  static getEncodedLength(inputLength: number, padding: boolean = true): number {
    const encodedLength = Math.ceil(inputLength / 3) * 4;
    if (!padding) {
      const paddingLength = (3 - (inputLength % 3)) % 3;
      return encodedLength - paddingLength;
    }
    return encodedLength;
  }

  static getDecodedLength(encodedInput: string): number {
    let length = Math.floor(encodedInput.length / 4) * 3;
    const padding = (encodedInput.match(/=/g) || []).length;
    return length - padding;
  }

  private static manualEncode(input: string, urlSafe: boolean, padding: boolean): Base64Result {
    try {
      const chars = urlSafe ? this.BASE64_URL_CHARS : this.BASE64_CHARS;
      let result = '';
      let i = 0;

      while (i < input.length) {
        const a = input.charCodeAt(i++);
        const b = i < input.length ? input.charCodeAt(i++) : 0;
        const c = i < input.length ? input.charCodeAt(i++) : 0;

        const bitmap = (a << 16) | (b << 8) | c;

        result += chars.charAt((bitmap >> 18) & 63);
        result += chars.charAt((bitmap >> 12) & 63);
        result += i - 2 < input.length ? chars.charAt((bitmap >> 6) & 63) : padding ? '=' : '';
        result += i - 1 < input.length ? chars.charAt(bitmap & 63) : padding ? '=' : '';
      }

      return {
        success: true,
        data: result
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Manual encoding failed'
      };
    }
  }

  private static manualDecode(input: string): Base64Result {
    try {
      let result = '';
      let i = 0;

      while (i < input.length) {
        const a = this.BASE64_CHARS.indexOf(input.charAt(i++));
        const b = this.BASE64_CHARS.indexOf(input.charAt(i++));
        const c = this.BASE64_CHARS.indexOf(input.charAt(i++));
        const d = this.BASE64_CHARS.indexOf(input.charAt(i++));

        const bitmap = (a << 18) | (b << 12) | (c << 6) | d;

        result += String.fromCharCode((bitmap >> 16) & 255);
        if (c !== 64) result += String.fromCharCode((bitmap >> 8) & 255);
        if (d !== 64) result += String.fromCharCode(bitmap & 255);
      }

      return {
        success: true,
        data: result
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Manual decoding failed'
      };
    }
  }

  private static stringToUtf8Bytes(str: string): number[] {
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      if (code < 0x80) {
        bytes.push(code);
      } else if (code < 0x800) {
        bytes.push(0xc0 | (code >> 6));
        bytes.push(0x80 | (code & 0x3f));
      } else if (code < 0xd800 || code >= 0xe000) {
        bytes.push(0xe0 | (code >> 12));
        bytes.push(0x80 | ((code >> 6) & 0x3f));
        bytes.push(0x80 | (code & 0x3f));
      } else {
        i++;
        const code2 = str.charCodeAt(i);
        const codePoint = 0x10000 + (((code & 0x3ff) << 10) | (code2 & 0x3ff));
        bytes.push(0xf0 | (codePoint >> 18));
        bytes.push(0x80 | ((codePoint >> 12) & 0x3f));
        bytes.push(0x80 | ((codePoint >> 6) & 0x3f));
        bytes.push(0x80 | (codePoint & 0x3f));
      }
    }
    return bytes;
  }

  private static utf8BytesToString(bytes: number[]): string {
    let result = '';
    let i = 0;
    
    while (i < bytes.length) {
      let c = bytes[i++];
      
      if (c < 0x80) {
        result += String.fromCharCode(c);
      } else if (c < 0xe0) {
        const c2 = bytes[i++];
        result += String.fromCharCode(((c & 0x1f) << 6) | (c2 & 0x3f));
      } else if (c < 0xf0) {
        const c2 = bytes[i++];
        const c3 = bytes[i++];
        result += String.fromCharCode(((c & 0x0f) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f));
      } else {
        const c2 = bytes[i++];
        const c3 = bytes[i++];
        const c4 = bytes[i++];
        const codePoint = ((c & 0x07) << 18) | ((c2 & 0x3f) << 12) | ((c3 & 0x3f) << 6) | (c4 & 0x3f);
        const surrogate1 = 0xd800 + ((codePoint - 0x10000) >> 10);
        const surrogate2 = 0xdc00 + ((codePoint - 0x10000) & 0x3ff);
        result += String.fromCharCode(surrogate1, surrogate2);
      }
    }
    
    return result;
  }

  static compare(base64a: string, base64b: string): boolean {
    const resultA = this.decode(base64a);
    const resultB = this.decode(base64b);
    
    if (!resultA.success || !resultB.success) {
      return false;
    }
    
    return resultA.data === resultB.data;
  }

  static concat(base64Values: string[]): Base64Result {
    try {
      let combinedData = '';
      
      for (const base64 of base64Values) {
        const result = this.decode(base64);
        if (!result.success) {
          return result;
        }
        combinedData += result.data;
      }
      
      return this.encode(combinedData);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Concatenation failed'
      };
    }
  }
}