import { zodResolver } from '@hookform/resolvers/zod'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { useParams } from 'react-router'
import { toast } from 'sonner'
import PageLoginMagicLink from '../ui/page-login-magic-link'
import { magicLinkSchema, MagicLinkSchema } from '../schemas/magic-link.schema'
import { useSendMagicLink } from '@/api/trident.api'

export default function PageLoginMagicLinkFeature() {
  const { realm_name } = useParams()
  const [isSuccess, setIsSuccess] = useState(false)

  const {
    mutate: sendMagicLink,
    status: sendStatus,
    error: sendError,
    isPending,
  } = useSendMagicLink()

  const form = useForm<MagicLinkSchema>({
    resolver: zodResolver(magicLinkSchema),
    defaultValues: {
      email: '',
    },
  })

  function onSubmit(data: MagicLinkSchema) {
    sendMagicLink(
      {
        path: {
          realm_name: realm_name ?? 'master',
        },
        body: {
          email: data.email,
        },
      },
      {
        onSuccess: () => {
          setIsSuccess(true)
          toast.success('Magic link sent! Check your email.')
        },
        onError: (error: Error) => {
          const message = error?.message || 'Failed to send magic link'
          toast.error(message)
        },
      }
    )
  }

  return (
    <PageLoginMagicLink
      form={form}
      onSubmit={onSubmit}
      isLoading={isPending}
      isSuccess={isSuccess}
      error={sendStatus === 'error' ? sendError?.message || 'Failed to send magic link' : null}
      loginSettings={{
        user_registration_enabled: false,
        forgot_password_enabled: false,
        remember_me_enabled: false,
        magic_link_enabled: true,
        magic_link_ttl_minutes: 60,
      }}
    />
  )
}
