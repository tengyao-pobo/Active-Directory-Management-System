import { useEffect, useRef, useState } from 'react';
import { ApiError, getFavorite, setFavorite } from './api';
import { useI18n } from './i18n';

function FavoriteButtonContent({ environmentId, id, onChanged }: { environmentId: string; id: string; onChanged?: () => void }) {
  const { t } = useI18n();
  const [saved, setSaved] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const lifetime = useRef<AbortController | null>(null);
  useEffect(() => {
    const controller = new AbortController(); lifetime.current = controller;
    void getFavorite(environmentId, id, controller.signal).then(value => { if (!controller.signal.aborted) setSaved(value.saved); })
      .catch(() => { if (!controller.signal.aborted) setError('favorites.unavailable'); });
    return () => controller.abort();
  }, [environmentId, id]);
  async function toggle() {
    const controller = lifetime.current;
    if (busy || !controller || controller.signal.aborted || saved === null) return;
    setBusy(true); setError('');
    try {
      await setFavorite(environmentId, id, !saved, controller.signal);
      if (!controller.signal.aborted) { setSaved(!saved); onChanged?.(); }
    } catch (failure) {
      if (!controller.signal.aborted) setError(failure instanceof ApiError && failure.code === 'FavoritesLimitReached' ? 'favorites.limit' : 'favorites.unavailable');
    } finally { if (!controller.signal.aborted) setBusy(false); }
  }
  return <div className="favorite-control"><button type="button" className="secondary-button" disabled={saved === null || busy} aria-pressed={saved ?? false} onClick={() => void toggle()}>
    {t(saved ? 'favorites.remove' : 'favorites.add')}</button>{error && <p role="alert">{t(error)}</p>}</div>;
}
export default function FavoriteButton(props: { environmentId: string; id: string; onChanged?: () => void }) {
  return <FavoriteButtonContent key={`${props.environmentId}:${props.id}`} {...props} />;
}
