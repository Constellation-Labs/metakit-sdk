/**
 * Tests for network operations
 */

import { NetworkError } from '../src';
import { MetagraphClient, createMetagraphClient, type LayerType } from '../src/network';

describe('Network Operations', () => {
  describe('MetagraphClient', () => {
    it('should require baseUrl in config', () => {
      expect(() => new MetagraphClient({ baseUrl: '', layer: 'dl1' })).toThrow(
        'baseUrl is required'
      );
    });

    it('should require layer in config', () => {
      expect(
        () => new MetagraphClient({ baseUrl: 'http://localhost:9400', layer: '' as LayerType })
      ).toThrow('layer is required');
    });

    it('should create client for dl1', () => {
      const client = new MetagraphClient({
        baseUrl: 'http://localhost:9400',
        layer: 'dl1',
      });
      expect(client).toBeInstanceOf(MetagraphClient);
      expect(client.getLayer()).toBe('dl1');
    });

    it('should create client for cl1', () => {
      const client = new MetagraphClient({
        baseUrl: 'http://localhost:9300',
        layer: 'cl1',
      });
      expect(client).toBeInstanceOf(MetagraphClient);
      expect(client.getLayer()).toBe('cl1');
    });

    it('should create client for ml0', () => {
      const client = new MetagraphClient({
        baseUrl: 'http://localhost:9200',
        layer: 'ml0',
      });
      expect(client).toBeInstanceOf(MetagraphClient);
      expect(client.getLayer()).toBe('ml0');
    });

    it('should accept optional timeout', () => {
      const client = new MetagraphClient({
        baseUrl: 'http://localhost:9400',
        layer: 'dl1',
        timeout: 5000,
      });
      expect(client).toBeInstanceOf(MetagraphClient);
    });

    describe('Layer-specific method guards', () => {
      it('should reject postData on cl1', () => {
        const client = new MetagraphClient({
          baseUrl: 'http://localhost:9300',
          layer: 'cl1',
        });
        expect(() => client.postData({ value: 'test', proofs: [] })).rejects.toThrow(
          'postData() is not available on CL1 layer'
        );
      });

      it('should reject postTransaction on dl1', () => {
        const client = new MetagraphClient({
          baseUrl: 'http://localhost:9400',
          layer: 'dl1',
        });
        const mockTx = {
          source: 'DAG...',
          destination: 'DAG...',
          amount: 100,
          fee: 0,
          parent: { hash: 'abc', ordinal: 1 },
          salt: 123,
        } as any;
        expect(() => client.postTransaction(mockTx)).rejects.toThrow(
          'postTransaction() is not available on DL1 layer'
        );
      });

      it('should reject estimateFee on cl1', () => {
        const client = new MetagraphClient({
          baseUrl: 'http://localhost:9300',
          layer: 'cl1',
        });
        expect(() => client.estimateFee({ value: 'test', proofs: [] })).rejects.toThrow(
          'estimateFee() is not available on CL1 layer'
        );
      });
    });
  });

  describe('createMetagraphClient helper', () => {
    it('should create client with convenience function', () => {
      const client = createMetagraphClient('http://localhost:9400', 'dl1');
      expect(client).toBeInstanceOf(MetagraphClient);
      expect(client.getLayer()).toBe('dl1');
    });

    it('should accept optional timeout', () => {
      const client = createMetagraphClient('http://localhost:9400', 'dl1', 10000);
      expect(client).toBeInstanceOf(MetagraphClient);
    });
  });

  describe('NetworkError', () => {
    it('should create error with message only', () => {
      const error = new NetworkError('Connection failed');
      expect(error.message).toBe('Connection failed');
      expect(error.name).toBe('NetworkError');
      expect(error.statusCode).toBeUndefined();
      expect(error.response).toBeUndefined();
    });

    it('should create error with status code', () => {
      const error = new NetworkError('Not found', 404);
      expect(error.message).toBe('Not found');
      expect(error.statusCode).toBe(404);
    });

    it('should create error with response body', () => {
      const error = new NetworkError('Bad request', 400, '{"error":"invalid"}');
      expect(error.message).toBe('Bad request');
      expect(error.statusCode).toBe(400);
      expect(error.response).toBe('{"error":"invalid"}');
    });

    it('should be instanceof Error', () => {
      const error = new NetworkError('Test');
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(NetworkError);
    });
  });

  describe('Combined usage', () => {
    it('should allow creating multiple clients for different layers', () => {
      const cl1 = createMetagraphClient('http://localhost:9300', 'cl1');
      const dl1 = createMetagraphClient('http://localhost:9400', 'dl1');
      const ml0 = createMetagraphClient('http://localhost:9200', 'ml0');

      expect(cl1).toBeInstanceOf(MetagraphClient);
      expect(dl1).toBeInstanceOf(MetagraphClient);
      expect(ml0).toBeInstanceOf(MetagraphClient);
      expect(cl1.getLayer()).toBe('cl1');
      expect(dl1.getLayer()).toBe('dl1');
      expect(ml0.getLayer()).toBe('ml0');
    });
  });
});
