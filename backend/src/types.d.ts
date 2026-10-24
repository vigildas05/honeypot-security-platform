// Type augmentation for JSDoc typechecking (`npm run typecheck`). Not compiled.
declare global {
  namespace Express {
    interface Request {
      user?: { id: string; username: string; role: "admin" | "demo" };
      sensorId?: string;
      id?: string;
    }
  }
}

export {};
