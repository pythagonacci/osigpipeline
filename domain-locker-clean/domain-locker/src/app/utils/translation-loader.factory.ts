import * as fs from 'fs';
import * as path from 'path';
import { inject, Injectable, PLATFORM_ID } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { isPlatformBrowser, isPlatformServer } from '@angular/common';
import { Observable, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import {
  TranslateLoader,
  TranslateService,
  MissingTranslationHandler,
  MissingTranslationHandlerParams,
} from '@ngx-translate/core';

@Injectable()
export class ServerSafeTranslateLoader implements TranslateLoader {
  private http = inject(HttpClient);
  private platformId = inject(PLATFORM_ID);

  getTranslation(lang: string): Observable<any> {
    // Client-Side: Use HttpClient to fetch translations from /i18n/
    if (isPlatformBrowser(this.platformId)) {
      const langRequestUrl = `/i18n/${lang}.json`;
      return this.http.get(langRequestUrl).pipe(catchError(() => of({})));
    }

    // Server-Side: Use fs to read translation files directly
    if (isPlatformServer(this.platformId)) {
      try {
        const filePath = path.join(process.cwd(), 'src/assets/i18n', `${lang}.json`);
        const data = fs.readFileSync(filePath, 'utf8');
        return of(JSON.parse(data));
      } catch (error) {
        console.error(`Error loading translation file for language "${lang}":`, error);
        return of({});
      }
    }

    // Fallback: Return an empty object if neither condition is met
    return of({});
  }
}

/** Handler for missing translations, used to log the error and return the fallback */
@Injectable({ providedIn: 'root' })
export class CustomMissingTranslationHandler implements MissingTranslationHandler {
  handle(params: MissingTranslationHandlerParams) {
    console.warn(`Missing translation for key: "${params.key}"`);
    return `[${params.key}]`;
  }
}

/** Initializes the language based on client or server environment */
export function languageInitializerFactory(translate: TranslateService, platformId: Object) {
  return () => {
    const defaultLang = 'en';
    if (isPlatformBrowser(platformId)) {
      const savedLanguage = localStorage?.getItem('language') || defaultLang;
      translate.setDefaultLang(defaultLang);
      translate.use(savedLanguage); 
    } else {
      translate.setDefaultLang(defaultLang);
    }
  };
}
