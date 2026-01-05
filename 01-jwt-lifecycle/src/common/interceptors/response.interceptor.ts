import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { IResponse } from '../interfaces/response.interface';

@Injectable()
export class ResponseInterceptor<T> implements NestInterceptor<T, IResponse<T>> {
  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<IResponse<T>> {
    const request = context.switchToHttp().getRequest();
    const statusCode = context.switchToHttp().getResponse().statusCode || 200;

    return next.handle().pipe(
      map((data) => {
        // Nếu data đã có format response rồi thì return luôn
        if (data && typeof data === 'object' && 'statusCode' in data) {
          return data as IResponse<T>;
        }

        // Transform thành format chuẩn
        const response: IResponse<T> = {
          statusCode,
          message: this.getSuccessMessage(request.method, statusCode),
          data: data || null,
          timestamp: new Date().toISOString(),
        };

        return response;
      }),
    );
  }

  private getSuccessMessage(method: string, statusCode: number): string {
    const messages: Record<string, Record<number, string>> = {
      GET: { 200: 'Data retrieved successfully' },
      POST: { 201: 'Resource created successfully', 200: 'Operation completed successfully' },
      PUT: { 200: 'Resource updated successfully' },
      PATCH: { 200: 'Resource updated successfully' },
      DELETE: { 200: 'Resource deleted successfully' },
    };

    return messages[method]?.[statusCode] || 'Operation completed successfully';
  }
}