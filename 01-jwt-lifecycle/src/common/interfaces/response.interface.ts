export interface IResponse<T=any> {
  statusCode: number;
  message: string;
  data?: T;
  error?: string;
  timestamp?: string;
}