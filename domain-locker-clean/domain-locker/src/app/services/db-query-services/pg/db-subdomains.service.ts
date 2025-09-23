import { catchError, forkJoin, from, map, Observable, of, switchMap, throwError } from 'rxjs';
import { PgApiUtilService } from '~/app/utils/pg-api.util';

export class SubdomainsQueries {
  constructor(
    private pgApiUtil: PgApiUtilService,
    private handleError: (error: any) => Observable<never>,
  ) {}

  saveSubdomainsForDomainName(
    domain: string,
    subdomains: { name: string; sd_info?: string }[]
  ): Observable<void> {
    return this.fetchDomainId(domain).pipe(
      switchMap((domainId) => from(this.saveSubdomains(domainId, subdomains))),
      catchError((error) => this.handleError(error))
    );
  }

  fetchDomainId(domain: string): Observable<string> {
    const query = `SELECT id FROM domains WHERE domain_name = $1 LIMIT 1`;
    const params = [domain];

    return from(this.pgApiUtil.postToPgExecutor(query, params)).pipe(
      map(({ data }: any) => {
        if (!data || data.length === 0) {
          throw new Error(`Domain ID not found for domain name: ${domain}`);
        }
        return data[0].id;
      }),
      catchError((error) => this.handleError(error))
    );
  }

  async saveSubdomains(domainId: string, subdomains: { name: string; sd_info?: string }[]): Promise<void> {
    if (!subdomains || subdomains.length === 0) {
      throw new Error('Skipping subdomains, none found');
    }

    const validSubdomains = subdomains.filter(sd => sd.name?.trim());
    if (validSubdomains.length === 0) {
      throw new Error('Skipping subdomains, no valid subdomains listed');
    }

    const query = `SELECT name FROM sub_domains WHERE domain_id = $1`;
    const params = [domainId];

    const { data: existingData } = await this.pgApiUtil.postToPgExecutor(query, params).toPromise() as any;
    const existingNames = (existingData || []).map((sd: { name: string }) => sd.name);

    const subdomainsToInsert = validSubdomains.filter(sd => !existingNames.includes(sd.name));

    if (subdomainsToInsert.length === 0) {
      throw new Error('Skipping subdomains, all already exist');
    }

    const insertQuery = `
      INSERT INTO sub_domains (domain_id, name, sd_info)
      VALUES ${subdomainsToInsert.map((_, i) => `($1, $${i * 2 + 2}, $${i * 2 + 3})`).join(', ')}
    `;
    const insertParams = [
      domainId,
      ...subdomainsToInsert.flatMap(sd => [sd.name, sd.sd_info || null])
    ];

    await this.pgApiUtil.postToPgExecutor(insertQuery, insertParams).toPromise();
  }

  async deleteSubdomainsByDomain(domain: string): Promise<void> {
    const domainId = await this.fetchDomainId(domain).toPromise();

    const query = `DELETE FROM sub_domains WHERE domain_id = $1`;
    const params = [domainId];

    await this.pgApiUtil.postToPgExecutor(query, params).toPromise();
  }

  async updateSubdomains(domainId: string, subdomains: { name: string; sd_info?: string }[]): Promise<void> {
    const query = `SELECT name, sd_info FROM sub_domains WHERE domain_id = $1`;
    const params = [domainId];

    const { data: existingData } = await this.pgApiUtil.postToPgExecutor(query, params).toPromise() as any;
    const existingSubdomains = existingData || [];

    const subdomainsToAdd = subdomains.filter(
      (sd) => !existingSubdomains.some((existing: any) => existing.name === sd.name)
    );

    const subdomainsToRemove = existingSubdomains
      .filter((existing: any) => !subdomains.some((sd) => sd.name === existing.name))
      .map((sd: any) => sd.name);

    if (subdomainsToAdd.length > 0) {
      const addQuery = `
        INSERT INTO sub_domains (domain_id, name, sd_info)
        VALUES ${subdomainsToAdd.map((_, i) => `($1, $${i * 2 + 2}, $${i * 2 + 3})`).join(', ')}
      `;
      const addParams = [
        domainId,
        ...subdomainsToAdd.flatMap(sd => [sd.name, sd.sd_info || null])
      ];

      await this.pgApiUtil.postToPgExecutor(addQuery, addParams).toPromise();
    }

    if (subdomainsToRemove.length > 0) {
      const removeQuery = `
        DELETE FROM sub_domains WHERE domain_id = $1 AND name = ANY($2)
      `;
      const removeParams = [domainId, subdomainsToRemove];

      await this.pgApiUtil.postToPgExecutor(removeQuery, removeParams).toPromise();
    }

    for (const sd of subdomains) {
      const existing = existingSubdomains.find((e: any) => e.name === sd.name);
      if (existing && sd.sd_info && sd.sd_info !== existing.sd_info) {
        const updateQuery = `
          UPDATE sub_domains SET sd_info = $1 WHERE domain_id = $2 AND name = $3
        `;
        const updateParams = [sd.sd_info, domainId, sd.name];

        await this.pgApiUtil.postToPgExecutor(updateQuery, updateParams).toPromise();
      }
    }
  }

  getAllSubdomains(): Observable<any[]> {
    const query = `
      SELECT DISTINCT
        sub_domains.name,
        sub_domains.sd_info,
        domains.domain_name
      FROM sub_domains
      INNER JOIN domains ON sub_domains.domain_id = domains.id
    `;
  
    return from(this.pgApiUtil.postToPgExecutor(query)).pipe(
      map(({ data }) => data || []),
      catchError((error) => this.handleError(error))
    );
  }

getSubdomainsByDomain(domain: string): Observable<any[]> {
  const query = `
    SELECT DISTINCT
      sub_domains.id,
      sub_domains.name,
      sub_domains.sd_info
    FROM sub_domains
    INNER JOIN domains ON sub_domains.domain_id = domains.id
    WHERE domains.domain_name = $1
  `;
  const params = [domain];

  return from(this.pgApiUtil.postToPgExecutor(query, params)).pipe(
    map(({ data }) => data || []),
    catchError((error) => this.handleError(error))
  );
}

  getSubdomainInfo(domain: string, subdomain: string): Observable<any> {
    const query = `
      SELECT sub_domains.name, sub_domains.sd_info, domains.domain_name
      FROM sub_domains
      INNER JOIN domains ON sub_domains.domain_id = domains.id
      WHERE domains.domain_name = $1 AND sub_domains.name = $2
    `;
    const params = [domain, subdomain];

    return from(this.pgApiUtil.postToPgExecutor(query, params)).pipe(
      map(({ data }) => {
        const firstResult = Array.isArray(data) && data.length > 0 ? data[0] : null as any;
        if (firstResult && firstResult.sd_info && typeof firstResult.sd_info === 'string') {
          try {
            firstResult.sd_info = JSON.parse(firstResult.sd_info);
          } catch (error) {
            this.handleError({ error, message: 'Failed to parse subdomain info' });
          }
        }
        return firstResult;
      }),
      catchError((error) => this.handleError(error))
    );
  }

  deleteSubdomain(domain: string, subdomain: string): Observable<void> {
    return this.fetchDomainId(domain).pipe(
      switchMap((domainId) => {
        const query = `DELETE FROM sub_domains WHERE domain_id = $1 AND name = $2`;
        const params = [domainId, subdomain];
        return this.pgApiUtil.postToPgExecutor(query, params); // presumably returns Observable<any>
      }),
      map(() => {}), // map result to void
      catchError((err) =>
        throwError(() => new Error(`Failed to delete subdomain: ${err.message || err}`))
      )
    );
  }

  saveSubdomainForDomain(domainName: string, subdomain: string): Observable<any> {
    const fetchDomainIdQuery = `
      SELECT id FROM domains WHERE domain_name = $1
    `;
    const insertSubdomainQuery = `
      INSERT INTO sub_domains (domain_id, name) VALUES ($1, $2)
    `;

    return from(this.pgApiUtil.postToPgExecutor(fetchDomainIdQuery, [domainName])).pipe(
      switchMap(({ data }: any) => {
        if (!data || data.length === 0) {
          return throwError(() => new Error(`Domain not found: ${domainName}`));
        }

        const domainId = data[0].id;
        return from(this.pgApiUtil.postToPgExecutor(insertSubdomainQuery, [domainId, subdomain]));
      }),
      catchError((error) => this.handleError(error))
    );
  }
}
