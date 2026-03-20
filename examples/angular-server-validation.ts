import { AbstractControl, FormArray, FormGroup } from '@angular/forms';

export type ApiValidationFieldErrors = Record<string, Record<string, unknown>>;

export interface ApiErrorPayload {
  code?: string;
  message?: string;
  fields?: ApiValidationFieldErrors;
}

export interface ApiErrorResponse {
  error?: ApiErrorPayload;
}

export function applyApiValidationErrors(form: AbstractControl, response: ApiErrorResponse): void {
  const error = response.error;
  if (!error || error.code !== 'validation_failed' || !error.fields) {
    return;
  }

  for (const [path, validators] of Object.entries(error.fields)) {
    const control = form.get(path);
    if (!control) {
      continue;
    }

    control.setErrors({
      ...(control.errors ?? {}),
      ...validators,
    });
    control.markAsTouched();
    control.markAsDirty();
  }
}

export function clearApiValidationErrors(control: AbstractControl): void {
  if (control instanceof FormGroup) {
    for (const child of Object.values(control.controls)) {
      clearApiValidationErrors(child);
    }
  }

  if (control instanceof FormArray) {
    for (const child of control.controls) {
      clearApiValidationErrors(child);
    }
  }

  const errors = control.errors;
  if (!errors) {
    return;
  }

  const nextErrors = { ...errors };
  delete nextErrors.required;
  delete nextErrors.email;
  delete nextErrors.minlength;
  delete nextErrors.maxlength;
  delete nextErrors.pattern;
  delete nextErrors.exclusive;

  control.setErrors(Object.keys(nextErrors).length > 0 ? nextErrors : null);
}

export function firstApiErrorMessage(errors: ValidationErrorsLike | null | undefined): string | null {
  if (!errors) {
    return null;
  }

  if (errors['required']) {
    return 'Required';
  }
  if (errors['email']) {
    return 'Enter a valid email address';
  }
  if (errors['minlength']) {
    return `Minimum length is ${String(errors['minlength']?.['requiredLength'] ?? '')}`.trim();
  }
  if (errors['maxlength']) {
    return `Maximum length is ${String(errors['maxlength']?.['requiredLength'] ?? '')}`.trim();
  }
  if (errors['pattern']) {
    return 'Invalid format';
  }
  if (errors['exclusive']) {
    return `Use either this field or ${String(errors['exclusive']?.['other'] ?? 'the paired field')}`;
  }

  return null;
}

type ValidationErrorsLike = Record<string, any>;