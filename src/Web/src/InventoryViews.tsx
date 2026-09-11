import { useState } from 'react';
import { useI18n } from './i18n';
import { formatInventoryBytes, hardwareFields, reportedInstallDate, type HardwareKind } from './inventoryDisplay';

export interface InventorySource {
  availability: 'Observed' | 'Missing' | 'Unavailable' | 'NotApplicable';
  freshness: 'Current' | 'Stale' | null;
  sourceObservedAt?: string | null; isTruncated?: boolean;
}
export interface HardwareSectionView extends InventorySource {
  kind: HardwareKind; rows: ReadonlyArray<Readonly<Record<string, string | null>>>;
}
export interface SoftwareApplicationView {
  name: string; version: string | null; publisher: string | null; installDate: string | null; architecture: string | null;
}
export interface BasicInventoryData {
  hostName: string | null;
  operatingSystem: { description: string | null; version: string | null; architecture: string | null };
  networkInterfaces: ReadonlyArray<{ name: string | null; interfaceType: string | null; macAddress: string | null;
    addresses: readonly string[]; gateways: readonly string[]; dnsServers: readonly string[] }>;
}

export function InventorySourceNote({ source }: { source: InventorySource }) {
  const { t, locale } = useI18n(); const date = source.sourceObservedAt ? new Date(source.sourceObservedAt) : null;
  return <>
    {source.availability !== 'Observed' && <p role="status" className="directory-notice">{t(`inventory.state.${source.availability}`)}</p>}
    {source.freshness === 'Stale' && <p role="status" className="directory-notice">{t('inventory.state.Stale')}</p>}
    {source.isTruncated && <p role="status" className="directory-notice">{t('inventory.incomplete')}</p>}
    {date && Number.isFinite(date.getTime()) && <p className="inventory-observed">{t('inventory.observedAt')}: {new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(date)}</p>}
  </>;
}
const hasObservation = (source: InventorySource) => source.availability === 'Observed';
const byteFields = new Set(['TotalPhysicalMemory', 'Capacity', 'AdapterRAM', 'Size']);

export function BasicInventoryView({ source, data }: { source: InventorySource; data: BasicInventoryData | null }) {
  const { t } = useI18n(); const text = (value: string | null | undefined) => value || t('inventory.unknown');
  return <section className="basic-inventory"><h4>{t('inventory.basic')}</h4><InventorySourceNote source={source} />
    {hasObservation(source) && data && <>
      <dl className="directory-detail-fields">
        <div><dt>{t('inventory.hostName')}</dt><dd>{text(data.hostName)}</dd></div>
        <div><dt>{t('inventory.osDescription')}</dt><dd>{text(data.operatingSystem.description)}</dd></div>
        <div><dt>{t('inventory.field.Version')}</dt><dd>{text(data.operatingSystem.version)}</dd></div>
        <div><dt>{t('inventory.osArchitecture')}</dt><dd>{text(data.operatingSystem.architecture)}</dd></div>
      </dl>
      <h5>{t('inventory.network')}</h5>
      {data.networkInterfaces.length === 0 ? <p>{t('inventory.noInterfaces')}</p> : data.networkInterfaces.map((network, index) => <details key={index} className="inventory-interface">
        <summary>{text(network.name)}</summary>
        <dl className="directory-detail-fields">
          <div><dt>{t('inventory.interfaceType')}</dt><dd>{text(network.interfaceType)}</dd></div>
          <div><dt>{t('inventory.macAddress')}</dt><dd>{text(network.macAddress)}</dd></div>
          {(['addresses', 'gateways', 'dnsServers'] as const).map(field => <div key={field}><dt>{t(`inventory.${field}`)}</dt>
            <dd>{network[field].length === 0 ? t('inventory.unknown') : <ul>{network[field].map((value, valueIndex) => <li key={valueIndex}>{value}</li>)}</ul>}</dd></div>)}
        </dl>
      </details>)}
    </>}
  </section>;
}

export function HardwareInventoryView({ sections }: { sections: ReadonlyArray<HardwareSectionView> }) {
  const { t } = useI18n();
  return <div className="hardware-inventory">{(Object.keys(hardwareFields) as HardwareKind[]).map(kind => {
    const section = sections.find(value => value.kind === kind) ?? { kind, availability: 'Missing' as const, freshness: null, rows: [] };
    return <details key={kind} className="inventory-section" open={kind === 'System'}><summary><span>{t(`inventory.section.${kind}`)}</span>
      <small>{t(`inventory.badge.${section.availability}`)}{section.freshness === 'Stale' ? ` · ${t('inventory.badge.Stale')}` : ''}</small>
    </summary><InventorySourceNote source={section} />
      {hasObservation(section) && (section.rows.length === 0 ? <p>{t('inventory.emptyRows')}</p> : section.rows.map((row, index) => <dl key={index} className="directory-detail-fields">
        {hardwareFields[kind].map(field => {
          const raw = row[field]; const value = byteFields.has(field) ? formatInventoryBytes(raw) : raw;
          return <div key={field}><dt>{t(`inventory.field.${field}`)}</dt><dd>{value == null || value === '' ? t('inventory.unknown') : value}</dd></div>;
        })}
      </dl>))}
    </details>;
  })}<p>{t('inventory.hardwareLimits')}</p></div>;
}

export function SoftwareInventoryView({ source, applications }: { source: InventorySource; applications: ReadonlyArray<SoftwareApplicationView> }) {
  const { t } = useI18n(); const [search, setSearch] = useState(''); const [page, setPage] = useState(0);
  const query = search.trim().toLocaleLowerCase();
  const matches = hasObservation(source) ? applications.filter(app => [app.name, app.version, app.publisher].some(value => value?.toLocaleLowerCase().includes(query))) : [];
  const pageCount = Math.max(1, Math.ceil(matches.length / 50)); const currentPage = Math.min(page, pageCount - 1);
  const text = (value: string | null) => value || t('inventory.unknown');
  return <section className="software-inventory"><h4>{t('inventory.software')}</h4><InventorySourceNote source={source} />
    {hasObservation(source) && <>
      <label>{t('inventory.searchSoftware')}<input type="search" maxLength={200} value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} /></label>
      <p>{t('inventory.matchCount', { count: matches.length })}</p>
      {matches.length === 0 ? <p role="status">{t(query ? 'inventory.noMatches' : 'inventory.noSoftware')}</p> : <div className="directory-table-panel"><div className="directory-table-scroll"><table>
        <thead><tr>{['name', 'version', 'publisher', 'installDate', 'architecture'].map(field => <th key={field} scope="col">{t(`inventory.software.${field}`)}</th>)}</tr></thead>
        <tbody>{matches.slice(currentPage * 50, currentPage * 50 + 50).map((app, index) => <tr key={index}>
          <td data-label={t('inventory.software.name')}>{app.name}</td>
          <td data-label={t('inventory.software.version')}>{text(app.version)}</td>
          <td data-label={t('inventory.software.publisher')}>{text(app.publisher)}</td>
          <td data-label={t('inventory.software.installDate')}>{text(reportedInstallDate(app.installDate))}</td>
          <td data-label={t('inventory.software.architecture')}>{text(app.architecture)}</td>
        </tr>)}</tbody>
      </table></div><div className="directory-pagination">
        <button type="button" className="secondary-button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>{t('directory.previous')}</button>
        <span>{t('inventory.page', { page: currentPage + 1, pages: pageCount })}</span>
        <button type="button" className="secondary-button" disabled={currentPage + 1 >= pageCount} onClick={() => setPage(currentPage + 1)}>{t('directory.next')}</button>
      </div></div>}
      <p>{t('inventory.softwareLimits')}</p>
    </>}
  </section>;
}
